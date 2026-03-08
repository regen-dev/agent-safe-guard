#include "sg/policy_bridge.hpp"

#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/rule_audit.hpp"

#include <optional>
#include <string>

namespace sg {
namespace {

void SetFieldIfPresent(Transaction* tx, std::string_view request_json,
                       std::string_view json_key,
                       std::string_view field_key = {}) {
  if (tx == nullptr) {
    return;
  }
  const auto value = FindJsonString(request_json, json_key);
  if (!value.has_value() || value->empty()) {
    return;
  }
  const std::string target_key =
      field_key.empty() ? std::string(json_key) : std::string(field_key);
  SetTransactionField(tx, target_key, *value);
}

}  // namespace

Transaction BuildBridgeTransaction(RulePhase phase, std::string_view request_json,
                                   std::string_view fallback_tool_name) {
  Transaction tx;
  tx.phase = phase;
  tx.raw_request_json = std::string(request_json);
  tx.session_id = FindJsonString(request_json, "session_id").value_or("");
  tx.tool_name =
      FindJsonString(request_json, "tool_name").value_or(std::string(fallback_tool_name));
  tx.transcript_path = FindJsonString(request_json, "transcript_path").value_or("");

  SetFieldIfPresent(&tx, request_json, "command");
  SetFieldIfPresent(&tx, request_json, "file_path");
  SetFieldIfPresent(&tx, request_json, "pattern");
  SetFieldIfPresent(&tx, request_json, "prompt");
  SetFieldIfPresent(&tx, request_json, "reason");
  SetFieldIfPresent(&tx, request_json, "agent_id");
  SetFieldIfPresent(&tx, request_json, "agent_type");
  SetFieldIfPresent(&tx, request_json, "worktree_path");

  return tx;
}

RuleAction InferBridgeAction(std::string_view response,
                             RuleAction default_action) {
  if (response.find("\"permissionDecision\":\"deny\"") != std::string_view::npos ||
      response.find("\"continue\": false") != std::string_view::npos ||
      response.find("\"continue\":false") != std::string_view::npos) {
    return RuleAction::kDeny;
  }
  if (response.find("\"modifyOutput\"") != std::string_view::npos) {
    return RuleAction::kModifyOutput;
  }
  if (response.find("\"suppressOutput\"") != std::string_view::npos) {
    return RuleAction::kSuppress;
  }
  return default_action;
}

void AppendBridgeRuleMatch(const Transaction& tx, const RuleMetadata& meta,
                           PackageMode mode, RuleAction action, bool enforced,
                           std::string_view message,
                           std::string_view matched_field,
                           std::string_view matched_value) {
  EvaluatedRule rule;
  rule.meta = meta;
  rule.mode = mode;
  rule.action = action;
  rule.enforced = enforced;
  rule.terminal = action == RuleAction::kDeny || action == RuleAction::kFailClosed;
  rule.message = std::string(message);
  rule.matched_field = std::string(matched_field);
  rule.matched_value = std::string(matched_value);
  AppendRuleMatchEvent(tx, rule);
}

std::string PassthroughResponse() {
  return std::string(kClientPassthroughResponse);
}

}  // namespace sg
