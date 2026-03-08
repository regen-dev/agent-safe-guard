#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace sg {

enum class RulePhase {
  kUnknown = 0,
  kPreToolUse,
  kPostToolUse,
  kPermissionRequest,
  kReadCompress,
  kReadGuard,
  kStop,
  kSessionStart,
  kSessionEnd,
  kPreCompact,
  kSubagentStart,
  kSubagentStop,
  kToolError,
};

enum class RuleSeverity {
  kInfo = 0,
  kLow,
  kMedium,
  kHigh,
  kCritical,
};

enum class RuleAction {
  kNone = 0,
  kAllow,
  kSuppress,
  kDeny,
  kModifyOutput,
  kAppendContext,
  kLogOnly,
  kFailClosed,
};

enum class PackageMode {
  kOff = 0,
  kDetectionOnly,
  kOn,
};

struct Transaction {
  RulePhase phase = RulePhase::kUnknown;
  std::string raw_request_json;
  std::string session_id;
  std::string tool_name;
  std::string transcript_path;
  std::unordered_map<std::string, std::string> fields;
};

struct RuleMetadata {
  int rule_id = 0;
  std::string package;
  std::string name;
  std::string description;
  RulePhase phase = RulePhase::kUnknown;
  RuleSeverity severity = RuleSeverity::kMedium;
  // Catalog rule matching fields (empty for built-in rules).
  std::string match_tool;    // e.g. "Bash", "" = any tool
  std::string match_field;   // e.g. "command", "lower_command"
  std::string pattern;       // regex pattern string
  std::string action_str;    // "deny", "log_only", etc.
  std::string message;       // human-readable block message
};

struct RuleOutcome {
  RuleAction action = RuleAction::kNone;
  bool terminal = false;
  std::string message;
  std::string matched_field;
  std::string matched_value;
  std::string response_payload;
};

struct EvaluatedRule {
  RuleMetadata meta;
  PackageMode mode = PackageMode::kOn;
  RuleAction action = RuleAction::kNone;
  bool terminal = false;
  bool enforced = false;
  std::string message;
  std::string matched_field;
  std::string matched_value;
  std::string response_payload;
};

inline void SetTransactionField(Transaction* tx, std::string key,
                                std::string value) {
  if (tx == nullptr) {
    return;
  }
  tx->fields[std::move(key)] = std::move(value);
}

inline std::optional<std::string_view> GetTransactionField(
    const Transaction& tx, std::string_view key) {
  const auto it = tx.fields.find(std::string(key));
  if (it == tx.fields.end()) {
    return std::nullopt;
  }
  return it->second;
}

constexpr std::string_view ToString(RulePhase phase) {
  switch (phase) {
    case RulePhase::kPreToolUse:
      return "pre_tool_use";
    case RulePhase::kPostToolUse:
      return "post_tool_use";
    case RulePhase::kPermissionRequest:
      return "permission_request";
    case RulePhase::kReadCompress:
      return "read_compress";
    case RulePhase::kReadGuard:
      return "read_guard";
    case RulePhase::kStop:
      return "stop";
    case RulePhase::kSessionStart:
      return "session_start";
    case RulePhase::kSessionEnd:
      return "session_end";
    case RulePhase::kPreCompact:
      return "pre_compact";
    case RulePhase::kSubagentStart:
      return "subagent_start";
    case RulePhase::kSubagentStop:
      return "subagent_stop";
    case RulePhase::kToolError:
      return "tool_error";
    case RulePhase::kUnknown:
    default:
      return "unknown";
  }
}

constexpr std::string_view ToString(RuleSeverity severity) {
  switch (severity) {
    case RuleSeverity::kInfo:
      return "info";
    case RuleSeverity::kLow:
      return "low";
    case RuleSeverity::kMedium:
      return "medium";
    case RuleSeverity::kHigh:
      return "high";
    case RuleSeverity::kCritical:
      return "critical";
    default:
      return "medium";
  }
}

constexpr std::string_view ToString(RuleAction action) {
  switch (action) {
    case RuleAction::kAllow:
      return "allow";
    case RuleAction::kSuppress:
      return "suppress";
    case RuleAction::kDeny:
      return "deny";
    case RuleAction::kModifyOutput:
      return "modify_output";
    case RuleAction::kAppendContext:
      return "append_context";
    case RuleAction::kLogOnly:
      return "log_only";
    case RuleAction::kFailClosed:
      return "fail_closed";
    case RuleAction::kNone:
    default:
      return "none";
  }
}

constexpr std::string_view ToString(PackageMode mode) {
  switch (mode) {
    case PackageMode::kOff:
      return "off";
    case PackageMode::kDetectionOnly:
      return "detection_only";
    case PackageMode::kOn:
    default:
      return "on";
  }
}

}  // namespace sg
