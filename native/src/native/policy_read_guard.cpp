#include "sg/policy_read_guard.hpp"

#include "sg/catalog_rule_compiler.hpp"
#include "sg/json_extract.hpp"
#include "sg/rule_audit.hpp"
#include "sg/rule_engine.hpp"

#include <charconv>
#include <cstdint>
#include <filesystem>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace sg {
namespace {

constexpr int kDefaultMaxSizeMb = 2;
constexpr std::string_view kPackageName = "read-defense";

bool EndsWith(std::string_view value, std::string_view suffix) {
  return value.size() >= suffix.size() &&
         value.substr(value.size() - suffix.size()) == suffix;
}

bool ContainsBundledPath(std::string_view path) {
  return path.find("node_modules/") != std::string_view::npos ||
         path.find("/dist/") != std::string_view::npos ||
         path.find("/build/") != std::string_view::npos ||
         path.find("expo-downloads/") != std::string_view::npos ||
         path.find("/vendor/") != std::string_view::npos ||
         path.find("/__generated__/") != std::string_view::npos ||
         EndsWith(path, ".min.js") || EndsWith(path, ".bundle.js") ||
         EndsWith(path, ".chunk.js") || EndsWith(path, "package-lock.json") ||
         EndsWith(path, "yarn.lock") || EndsWith(path, "pnpm-lock.yaml") ||
         EndsWith(path, "Cargo.lock") || EndsWith(path, "poetry.lock") ||
         EndsWith(path, "composer.lock") || EndsWith(path, "Gemfile.lock") ||
         EndsWith(path, "go.sum");
}

int ParseMaxSizeMb(const std::string& raw) {
  if (raw.empty()) {
    return kDefaultMaxSizeMb;
  }

  int value = 0;
  const auto* begin = raw.data();
  const auto* end = raw.data() + raw.size();
  const auto [ptr, ec] = std::from_chars(begin, end, value);
  if (ec != std::errc() || ptr != end || value <= 0) {
    return kDefaultMaxSizeMb;
  }
  return value;
}

std::string JsonAllow() { return "{\"decision\":\"allow\"}"; }

std::string JsonDeny(std::string_view message) {
  return "{\"decision\":\"deny\",\"message\":\"" + JsonEscape(message) +
         "\",\"exit_code\":\"2\"}";
}

std::string_view FieldOrEmpty(const Transaction& tx, std::string_view key) {
  const auto value = GetTransactionField(tx, key);
  if (!value.has_value()) {
    return {};
  }
  return *value;
}

CompiledRule MakeRule(int rule_id, std::string name, RuleSeverity severity,
                      RuleMatcher matcher) {
  CompiledRule rule;
  rule.meta.rule_id = rule_id;
  rule.meta.package = std::string(kPackageName);
  rule.meta.name = std::move(name);
  rule.meta.phase = RulePhase::kReadGuard;
  rule.meta.severity = severity;
  rule.match = std::move(matcher);
  return rule;
}

Transaction BuildTransaction(std::string_view request_json) {
  Transaction tx;
  tx.phase = RulePhase::kReadGuard;
  tx.raw_request_json = std::string(request_json);
  tx.session_id = FindJsonString(request_json, "session_id").value_or("");
  tx.tool_name = FindJsonString(request_json, "tool_name").value_or("");
  tx.transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");

  const std::string file_path =
      FindJsonString(request_json, "file_path").value_or("");
  const int max_size_mb = ParseMaxSizeMb(
      FindJsonString(request_json, "sg_read_guard_max_mb")
          .value_or(std::to_string(kDefaultMaxSizeMb)));

  SetTransactionField(&tx, "file_path", file_path);
  SetTransactionField(&tx, "max_size_mb", std::to_string(max_size_mb));
  return tx;
}

std::vector<CompiledRule> BuildRules() {
  std::vector<CompiledRule> rules;

  rules.push_back(MakeRule(
      300100, "bundled_generated_path", RuleSeverity::kHigh,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view file_path = FieldOrEmpty(tx, "file_path");
        if (file_path.empty() || !ContainsBundledPath(file_path)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked: '" + std::string(file_path) +
                          "' is a bundled/generated file; find the source";
        outcome.matched_field = "tool_input.file_path";
        outcome.matched_value = std::string(file_path);
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      300110, "oversize_regular_file", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string file_path(FieldOrEmpty(tx, "file_path"));
        if (file_path.empty()) {
          return std::nullopt;
        }

        const int max_size_mb =
            ParseMaxSizeMb(std::string(FieldOrEmpty(tx, "max_size_mb")));
        const std::uint64_t max_size_bytes =
            static_cast<std::uint64_t>(max_size_mb) * 1024ULL * 1024ULL;

        const std::filesystem::path path(file_path);
        std::error_code ec;
        const bool exists = std::filesystem::exists(path, ec);
        if (ec) {
          return std::nullopt;
        }

        const bool is_regular_file =
            exists && std::filesystem::is_regular_file(path, ec);
        if (ec || !is_regular_file) {
          return std::nullopt;
        }

        const std::uintmax_t file_size = std::filesystem::file_size(path, ec);
        if (ec || file_size <= max_size_bytes) {
          return std::nullopt;
        }

        std::ostringstream size_mb;
        size_mb << std::fixed << std::setprecision(1)
                << (static_cast<double>(file_size) / 1024.0 / 1024.0);

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked: '" + file_path + "' is " + size_mb.str() +
                          "MB (max " + std::to_string(max_size_mb) + "MB)";
        outcome.matched_field = "tool_input.file_path";
        outcome.matched_value = file_path;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  return rules;
}

void AppendAudit(const Transaction& tx, const EngineResult& result) {
  for (const auto& match : result.matches) {
    AppendRuleMatchEvent(tx, match);
  }
  for (const auto& error : result.errors) {
    AppendRuleErrorEvent(tx, error);
  }
}

}  // namespace

std::string EvaluateReadGuard(std::string_view request_json) {
  const Transaction tx = BuildTransaction(request_json);
  std::vector<CompiledRule> rules = BuildRules();
  const auto catalog_rules = GetCatalogCompiledRules(RulePhase::kReadGuard);
  rules.insert(rules.end(), catalog_rules.begin(), catalog_rules.end());
  const EngineResult result = EvaluateRules(tx, rules);
  AppendAudit(tx, result);

  if (result.enforced.has_value()) {
    return result.enforced->response_payload;
  }
  return JsonAllow();
}

std::vector<RuleMetadata> ListReadGuardRules() {
  std::vector<RuleMetadata> metadata;
  for (const auto& rule : BuildRules()) {
    metadata.push_back(rule.meta);
  }
  const auto catalog = ListCatalogRulesForPhase(RulePhase::kReadGuard);
  metadata.insert(metadata.end(), catalog.begin(), catalog.end());
  return metadata;
}

}  // namespace sg
