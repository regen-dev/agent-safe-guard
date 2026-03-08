#include "sg/rule_audit.hpp"

#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_stats.hpp"

#include <filesystem>
#include <optional>
#include <sstream>
#include <string_view>

namespace sg {
namespace {

std::optional<std::string_view> FirstNonEmpty(
    std::optional<std::string_view> first,
    std::optional<std::string_view> second = std::nullopt) {
  if (first.has_value() && !first->empty()) {
    return first;
  }
  if (second.has_value() && !second->empty()) {
    return second;
  }
  return std::nullopt;
}

void AppendJsonField(std::ostringstream* out, std::string_view key,
                     std::string_view value) {
  if (out == nullptr || value.empty()) {
    return;
  }
  *out << ",\"" << key << "\":\"" << JsonEscape(value) << "\"";
}

void AppendJsonBoolField(std::ostringstream* out, std::string_view key,
                         bool value) {
  if (out == nullptr) {
    return;
  }
  *out << ",\"" << key << "\":" << (value ? "true" : "false");
}

std::string RuleDisposition(const EvaluatedRule& rule) {
  if (rule.mode == PackageMode::kOff) {
    return "bypassed";
  }
  if (rule.mode == PackageMode::kDetectionOnly) {
    return "detect_only";
  }
  if (!rule.enforced) {
    return "observed";
  }

  switch (rule.action) {
    case RuleAction::kAllow:
      return "allowed";
    case RuleAction::kSuppress:
      return "suppressed";
    case RuleAction::kModifyOutput:
      return "modified";
    case RuleAction::kDeny:
    case RuleAction::kFailClosed:
      return "blocked";
    case RuleAction::kAppendContext:
    case RuleAction::kLogOnly:
    case RuleAction::kNone:
    default:
      return "observed";
  }
}

bool IsSubagentTranscript(std::string_view transcript_path) {
  return transcript_path.find("/subagents/") != std::string_view::npos ||
         transcript_path.find("/tmp/") != std::string_view::npos;
}

std::string ProjectRootFromTranscriptPath(std::string_view transcript_path) {
  if (transcript_path.empty()) {
    return "";
  }

  const std::filesystem::path transcript{std::string(transcript_path)};
  if (transcript_path.find("/subagents/") != std::string_view::npos) {
    return transcript.parent_path().parent_path().string();
  }
  return transcript.parent_path().string();
}

}  // namespace

void AppendRuleMatchEvent(const Transaction& tx, const EvaluatedRule& rule) {
  const std::string disposition = RuleDisposition(rule);
  std::ostringstream event;
  event << "{\"event_type\":\"rule_match\",\"timestamp\":" << UnixNow()
        << ",\"phase\":\"" << ToString(rule.meta.phase) << "\""
        << ",\"package\":\"" << JsonEscape(rule.meta.package) << "\""
        << ",\"rule_id\":" << rule.meta.rule_id
        << ",\"rule_name\":\"" << JsonEscape(rule.meta.name) << "\""
        << ",\"mode\":\"" << ToString(rule.mode) << "\""
        << ",\"action\":\"" << ToString(rule.action) << "\""
        << ",\"severity\":\"" << ToString(rule.meta.severity) << "\""
        << ",\"disposition\":\"" << JsonEscape(disposition) << "\"";

  AppendJsonBoolField(&event, "enforced", rule.enforced);

  AppendJsonField(&event, "session_id", tx.session_id);
  AppendJsonField(&event, "tool", tx.tool_name);
  AppendJsonField(&event, "message", rule.message);
  AppendJsonField(&event, "matched_field", rule.matched_field);
  AppendJsonField(&event, "matched_value", rule.matched_value);
  if (!tx.transcript_path.empty()) {
    AppendJsonField(&event, "transcript_path", tx.transcript_path);
  }
  AppendJsonField(&event, "project_root",
                  ProjectRootFromTranscriptPath(tx.transcript_path));
  AppendJsonBoolField(&event, "is_subagent",
                      IsSubagentTranscript(tx.transcript_path));
  const auto agent_type = GetTransactionField(tx, "agent_type");
  if (agent_type.has_value() && !agent_type->empty()) {
    AppendJsonField(&event, "agent_type", *agent_type);
  }

  const auto file_path =
      FirstNonEmpty(GetTransactionField(tx, "file_path"), std::nullopt);
  if (file_path.has_value()) {
    AppendJsonField(&event, "file_path", *file_path);
  }

  const auto command = FirstNonEmpty(GetTransactionField(tx, "command"));
  if (command.has_value()) {
    AppendJsonField(&event, "command", *command);
  }

  event << "}";
  AppendEventLine(DefaultEventsFilePath(), event.str());
  UpdateRuleMatchStats(tx, rule);
}

void AppendRuleErrorEvent(const Transaction& tx, const RuleEngineError& error) {
  std::ostringstream event;
  event << "{\"event_type\":\"rule_error\",\"timestamp\":" << UnixNow()
        << ",\"phase\":\"" << ToString(error.meta.phase) << "\""
        << ",\"package\":\"" << JsonEscape(error.meta.package) << "\""
        << ",\"rule_id\":" << error.meta.rule_id
        << ",\"rule_name\":\"" << JsonEscape(error.meta.name) << "\""
        << ",\"severity\":\"" << ToString(error.meta.severity) << "\""
        << ",\"message\":\"" << JsonEscape(error.message) << "\"";
  if (!tx.session_id.empty()) {
    event << ",\"session_id\":\"" << JsonEscape(tx.session_id) << "\"";
  }
  if (!tx.tool_name.empty()) {
    event << ",\"tool\":\"" << JsonEscape(tx.tool_name) << "\"";
  }
  const auto command = GetTransactionField(tx, "command");
  if (command.has_value() && !command->empty()) {
    event << ",\"command\":\"" << JsonEscape(*command) << "\"";
  }
  event << "}";
  AppendEventLine(DefaultEventsFilePath(), event.str());
  UpdateRuleErrorStats(tx, error);
}

}  // namespace sg
