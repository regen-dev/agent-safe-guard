#include "sg/policy_permission_request.hpp"

#include "sg/catalog_rule_compiler.hpp"
#include "sg/json_extract.hpp"
#include "sg/rule_audit.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace sg {
namespace {

constexpr std::string_view kPackageName = "approval-defense";

std::string NormalizeSpaces(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  bool in_space = false;
  for (const unsigned char ch : input) {
    if (std::isspace(ch) != 0) {
      if (!in_space) {
        out.push_back(' ');
        in_space = true;
      }
    } else {
      out.push_back(static_cast<char>(ch));
      in_space = false;
    }
  }
  while (!out.empty() && out.front() == ' ') {
    out.erase(out.begin());
  }
  while (!out.empty() && out.back() == ' ') {
    out.pop_back();
  }
  return out;
}

std::string Lower(std::string_view input) {
  std::string out(input);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

bool ContainsAny(std::string_view haystack,
                 const std::vector<std::string_view>& needles) {
  for (const auto needle : needles) {
    if (haystack.find(needle) != std::string_view::npos) {
      return true;
    }
  }
  return false;
}

std::string JsonDeny(std::string_view msg) {
  return "{\"hookSpecificOutput\":{\"hookEventName\":\"PermissionRequest\",\"decision\":{\"behavior\":\"deny\",\"message\":\"" +
         JsonEscape(msg) + "\"}}}";
}

std::string JsonAllow() {
  return "{\"hookSpecificOutput\":{\"hookEventName\":\"PermissionRequest\",\"decision\":{\"behavior\":\"allow\"}}}";
}

std::string JsonSuppress() { return "{\"suppressOutput\":true}"; }

bool StartsWith(std::string_view value, std::string_view prefix) {
  return value.size() >= prefix.size() &&
         value.substr(0, prefix.size()) == prefix;
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
  rule.meta.phase = RulePhase::kPermissionRequest;
  rule.meta.severity = severity;
  rule.match = std::move(matcher);
  return rule;
}

Transaction BuildTransaction(std::string_view request_json) {
  Transaction tx;
  tx.phase = RulePhase::kPermissionRequest;
  tx.raw_request_json = std::string(request_json);
  tx.session_id = FindJsonString(request_json, "session_id").value_or("");
  tx.tool_name = FindJsonString(request_json, "tool_name").value_or("");
  tx.transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");

  const std::string command = FindJsonString(request_json, "command").value_or("");
  const std::string normalized = NormalizeSpaces(command);
  const std::string lower = Lower(normalized);

  SetTransactionField(&tx, "command", command);
  SetTransactionField(&tx, "normalized_command", normalized);
  SetTransactionField(&tx, "lower_command", lower);
  return tx;
}

std::vector<CompiledRule> BuildRules() {
  std::vector<CompiledRule> rules;

  rules.push_back(MakeRule(
      200100, "destructive_command", RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view lower = FieldOrEmpty(tx, "lower_command");
        if (!ContainsAny(lower,
                         {"rm -rf /", "rm -fr /", "rm -rf ~", "rm -fr ~",
                          "rm -rf --no-preserve-root", "mkfs", "dd if=",
                          "> /dev/sd", "> /dev/nvme", "chmod -r 777 /",
                          "chown -r "})) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked destructive command";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      200110, "fork_bomb", RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view normalized = FieldOrEmpty(tx, "normalized_command");
        if (!ContainsAny(normalized, {":(){:|:&};:", ":(){ :|:&};:"})) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked fork bomb";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      200120, "remote_code_execution", RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view lower = FieldOrEmpty(tx, "lower_command");
        const bool has_pipe_rce =
            ((lower.find("curl") != std::string_view::npos ||
              lower.find("wget") != std::string_view::npos) &&
             ContainsAny(lower, {"| bash", "| sh", "bash <(curl", "sh <(curl",
                                 "bash <(wget", "sh <(wget", "&& bash",
                                 "&& sh"}));
        if (!has_pipe_rce) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked remote code execution";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      200200, "allow_safe_introspection", RuleSeverity::kLow,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view lower = FieldOrEmpty(tx, "lower_command");
        if (!(lower == "whoami" || lower == "hostname" || lower == "locale" ||
              StartsWith(lower, "type ") || StartsWith(lower, "man "))) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kAllow;
        outcome.terminal = true;
        outcome.message = "Auto-approved safe introspection command";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonAllow();
        return outcome;
      }));

  rules.push_back(MakeRule(
      200210, "allow_literal_echo", RuleSeverity::kLow,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view lower = FieldOrEmpty(tx, "lower_command");
        if (!(lower == "echo" || lower == "echo -n" || StartsWith(lower, "echo ") ||
              StartsWith(lower, "echo -n "))) {
          return std::nullopt;
        }

        std::string payload(FieldOrEmpty(tx, "normalized_command"));
        if (StartsWith(payload, "echo")) {
          payload.erase(0, 4);
          if (StartsWith(payload, " -n")) {
            payload.erase(0, 3);
          }
          while (!payload.empty() && payload.front() == ' ') {
            payload.erase(payload.begin());
          }
        }

        if (payload.find_first_of("$`\\(){}[]*?;|&<>") != std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kAllow;
        outcome.terminal = true;
        outcome.message = "Auto-approved literal echo";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonAllow();
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

std::string EvaluatePermissionRequest(std::string_view request_json) {
  const Transaction tx = BuildTransaction(request_json);
  std::vector<CompiledRule> rules = BuildRules();
  const auto catalog_rules =
      GetCatalogCompiledRules(RulePhase::kPermissionRequest);
  rules.insert(rules.end(), catalog_rules.begin(), catalog_rules.end());
  const EngineResult result = EvaluateRules(tx, rules);
  AppendAudit(tx, result);

  if (result.enforced.has_value()) {
    return result.enforced->response_payload;
  }
  return JsonSuppress();
}

std::vector<RuleMetadata> ListPermissionRequestRules() {
  std::vector<RuleMetadata> metadata;
  for (const auto& rule : BuildRules()) {
    metadata.push_back(rule.meta);
  }
  const auto catalog = ListCatalogRulesForPhase(RulePhase::kPermissionRequest);
  metadata.insert(metadata.end(), catalog.begin(), catalog.end());
  return metadata;
}

}  // namespace sg
