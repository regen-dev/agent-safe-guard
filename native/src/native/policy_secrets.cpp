#include "sg/policy_secrets.hpp"

#include "sg/json_extract.hpp"
#include "sg/policy_bridge.hpp"
#include "sg/rule_audit.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace sg {
namespace {

constexpr std::string_view kPackageName = "secrets-defense";
constexpr int kMaskPrefixLen = 4;

// -- helpers ----------------------------------------------------------------

bool EndsWith(std::string_view value, std::string_view suffix) {
  return value.size() >= suffix.size() &&
         value.substr(value.size() - suffix.size()) == suffix;
}

std::string_view Basename(std::string_view path) {
  const auto slash = path.find_last_of('/');
  return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

// -- credential file detection -----------------------------------------------

bool IsCredentialFile(std::string_view path) {
  const auto name = Basename(path);
  // Private keys and certificates.
  if (EndsWith(name, ".pem") || EndsWith(name, ".key") ||
      EndsWith(name, ".p12") || EndsWith(name, ".pfx") ||
      EndsWith(name, ".jks") || EndsWith(name, ".keystore")) {
    return true;
  }
  // SSH keys.
  if (name == "id_rsa" || name == "id_ecdsa" || name == "id_ed25519" ||
      name == "id_dsa" || name == "authorized_keys") {
    return true;
  }
  // Cloud / service credentials.
  if (name == "credentials.json" || name == "service-account.json" ||
      name == "service_account.json" || name == "gcloud-credentials.json") {
    return true;
  }
  // Token / secret files.
  if (name == ".npmrc" || name == ".pypirc" || name == ".netrc" ||
      name == ".docker/config.json") {
    return true;
  }
  return false;
}

// -- .env file detection -----------------------------------------------------

bool IsEnvFile(std::string_view path) {
  const auto name = Basename(path);
  // Exact matches: .env, .env.local, .env.production, etc.
  if (name == ".env" || (name.size() > 4 && name.substr(0, 5) == ".env.")) {
    return true;
  }
  // Files ending in .env (e.g. app.env, docker.env).
  if (EndsWith(name, ".env")) {
    return true;
  }
  return false;
}

// -- value masking -----------------------------------------------------------

// Mask a single value, keeping up to kMaskPrefixLen visible chars.
// Empty and short values get fully masked.
std::string MaskValue(std::string_view value) {
  // Strip surrounding quotes if present.
  std::string_view inner = value;
  if (inner.size() >= 2 &&
      ((inner.front() == '"' && inner.back() == '"') ||
       (inner.front() == '\'' && inner.back() == '\''))) {
    inner = inner.substr(1, inner.size() - 2);
  }
  if (inner.empty()) {
    return "****";
  }
  const std::size_t visible =
      std::min(static_cast<std::size_t>(kMaskPrefixLen), inner.size());
  return std::string(inner.substr(0, visible)) + "****";
}

// Transform .env content: keep keys, mask values after '='.
// Lines that are comments (#) or blank pass through unchanged.
std::string MaskEnvContent(std::string_view content) {
  std::istringstream in{std::string(content)};
  std::ostringstream out;
  std::string line;
  bool first = true;

  while (std::getline(in, line)) {
    if (!first) {
      out << '\n';
    }
    first = false;

    // Blank or comment lines pass through.
    const auto first_nonspace = line.find_first_not_of(" \t");
    if (first_nonspace == std::string::npos || line[first_nonspace] == '#') {
      out << line;
      continue;
    }

    // export KEY=VALUE -> export KEY=masked
    std::string_view view(line);
    std::string prefix;
    if (view.substr(0, 7) == "export " || view.substr(0, 7) == "Export ") {
      prefix = std::string(view.substr(0, 7));
      view = view.substr(7);
    }

    const auto eq = view.find('=');
    if (eq == std::string_view::npos) {
      out << line;  // Not a KEY=VALUE line.
      continue;
    }

    const auto key = view.substr(0, eq);
    const auto value = view.substr(eq + 1);
    out << prefix << key << '=' << MaskValue(value);
  }

  return out.str();
}

// -- JSON helpers -----------------------------------------------------------

std::string JsonDeny(std::string_view message) {
  return "{\"decision\":\"deny\",\"message\":\"" + JsonEscape(message) +
         "\",\"exit_code\":\"2\"}";
}

std::string JsonModify(std::string_view text) {
  return "{\"modifyOutput\":\"" + JsonEscape(text) + "\"}";
}

std::string_view FieldOrEmpty(const Transaction& tx, std::string_view key) {
  const auto value = GetTransactionField(tx, key);
  return value.has_value() ? *value : std::string_view{};
}

// -- rules -------------------------------------------------------------------

CompiledRule MakeRule(int rule_id, std::string name, RulePhase phase,
                      RuleSeverity severity, RuleMatcher matcher) {
  CompiledRule rule;
  rule.meta.rule_id = rule_id;
  rule.meta.package = std::string(kPackageName);
  rule.meta.name = std::move(name);
  rule.meta.phase = phase;
  rule.meta.severity = severity;
  rule.match = std::move(matcher);
  return rule;
}

std::vector<CompiledRule> BuildReadGuardRules() {
  std::vector<CompiledRule> rules;

  rules.push_back(MakeRule(
      500100, "credentials_file_block", RulePhase::kReadGuard,
      RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view file_path = FieldOrEmpty(tx, "file_path");
        if (file_path.empty() || !IsCredentialFile(file_path)) {
          return std::nullopt;
        }
        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message =
            "Blocked: '" + std::string(file_path) +
            "' is a credential/key file; access denied for safety";
        outcome.matched_field = "tool_input.file_path";
        outcome.matched_value = std::string(file_path);
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  return rules;
}

static const RuleMetadata kEnvMaskingRule = {
    500200,
    std::string(kPackageName),
    "env_value_masking",
    "",
    RulePhase::kReadCompress,
    RuleSeverity::kHigh,
};

// -- evaluation entry points ------------------------------------------------

Transaction BuildTransaction(RulePhase phase, std::string_view request_json) {
  Transaction tx;
  tx.phase = phase;
  tx.raw_request_json = std::string(request_json);
  tx.session_id = FindJsonString(request_json, "session_id").value_or("");
  tx.tool_name = FindJsonString(request_json, "tool_name").value_or("");
  tx.transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");
  const std::string file_path =
      FindJsonString(request_json, "file_path").value_or("");
  SetTransactionField(&tx, "file_path", file_path);
  return tx;
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

std::string EvaluateSecretsReadGuard(std::string_view request_json) {
  const Transaction tx = BuildTransaction(RulePhase::kReadGuard, request_json);
  const auto rules = BuildReadGuardRules();
  const EngineResult result = EvaluateRules(tx, rules);
  AppendAudit(tx, result);
  if (result.enforced.has_value()) {
    return result.enforced->response_payload;
  }
  return "";  // No match — let other read_guard rules proceed.
}

std::string EvaluateSecretsReadCompress(std::string_view request_json) {
  const std::string tool_name =
      FindJsonString(request_json, "tool_name").value_or("");
  if (tool_name != "Read") {
    return "";
  }

  const std::string file_path =
      FindJsonString(request_json, "file_path").value_or("");
  if (!IsEnvFile(file_path)) {
    return "";
  }

  const std::string content =
      FindJsonString(request_json, "text").value_or("");
  if (content.empty()) {
    return "";
  }

  const Transaction tx =
      BuildTransaction(RulePhase::kReadCompress, request_json);
  const PackageMode mode = ResolveEffectiveRuleMode(kEnvMaskingRule);
  if (mode == PackageMode::kOff) {
    return "";
  }

  const std::string masked = MaskEnvContent(content);
  const std::string header =
      "[secrets-defense: .env values masked — keys and partial prefixes shown]\n\n";
  const std::string response = JsonModify(header + masked);

  AppendBridgeRuleMatch(tx, kEnvMaskingRule, mode, RuleAction::kModifyOutput,
                        mode == PackageMode::kOn, "env value masking applied");

  if (mode != PackageMode::kOn) {
    return "";  // Detection-only: logged but not enforced.
  }
  return response;
}

std::vector<RuleMetadata> ListSecretsRules() {
  std::vector<RuleMetadata> metadata;
  for (const auto& rule : BuildReadGuardRules()) {
    metadata.push_back(rule.meta);
  }
  metadata.push_back(kEnvMaskingRule);
  return metadata;
}

}  // namespace sg
