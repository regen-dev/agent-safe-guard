#include "sg/policy_tool_error.hpp"

#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_bridge.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace sg {
namespace {

const RuleMetadata kToolErrorRule = {
    400130,
    "telemetry",
    "tool_error_telemetry",
    "",
    RulePhase::kToolError,
    RuleSeverity::kLow,
};

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

void WriteFile(const std::filesystem::path& path, const std::string& content) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::trunc | std::ios::binary);
  if (!out) {
    return;
  }
  out << content;
}

void AppendLine(const std::filesystem::path& path, const std::string& line) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::app);
  if (!out) {
    return;
  }
  out << line << "\n";
}

long SessionStartSFromState(const std::filesystem::path& state_dir) {
  const std::string raw = ReadFile(state_dir / ".session_start");
  if (raw.empty()) {
    return UnixNow();
  }
  const auto dot = raw.find('.');
  try {
    return std::stol(raw.substr(0, dot));
  } catch (...) {
    return UnixNow();
  }
}

std::string TimestampNow() {
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
  localtime_r(&now, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%c", &tm);
  return std::string(buf);
}

std::string SanitizeId(std::string_view id) {
  std::string out;
  out.reserve(id.size());
  for (const unsigned char ch : id) {
    if (std::isalnum(ch) != 0 || ch == '_' || ch == '-') {
      out.push_back(static_cast<char>(ch));
    }
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

void RotateErrorLog(const std::filesystem::path& error_log) {
  std::ifstream in(error_log);
  if (!in) {
    return;
  }
  std::vector<std::string> lines;
  std::string line;
  while (std::getline(in, line)) {
    lines.push_back(line);
  }
  if (lines.size() <= 1500) {
    return;
  }
  const std::size_t start = lines.size() > 1000 ? (lines.size() - 1000) : 0;
  std::ostringstream out;
  for (std::size_t i = start; i < lines.size(); ++i) {
    out << lines[i] << "\n";
  }
  WriteFile(error_log, out.str());
}

}  // namespace

std::string EvaluateToolErrorImpl(std::string_view request_json) {
  if (request_json.empty()) {
    return "";
  }

  const std::string home =
      FindJsonString(request_json, "sg_home")
          .value_or(std::getenv("HOME") != nullptr ? std::getenv("HOME") : "");
  const std::string state_dir_raw =
      FindJsonString(request_json, "sg_state_dir")
          .value_or(std::getenv("SG_STATE_DIR") != nullptr
                        ? std::getenv("SG_STATE_DIR")
                        : "");
  const std::string events_file_raw =
      FindJsonString(request_json, "sg_events_file")
          .value_or(std::getenv("SG_EVENTS_FILE") != nullptr
                        ? std::getenv("SG_EVENTS_FILE")
                        : "");
  const std::string pwd =
      FindJsonString(request_json, "sg_pwd")
          .value_or(std::getenv("PWD") != nullptr ? std::getenv("PWD") : "");

  const std::filesystem::path state_dir =
      !state_dir_raw.empty() ? std::filesystem::path(state_dir_raw)
                             : std::filesystem::path(home) / ".claude/.statusline";
  const std::filesystem::path events_file =
      !events_file_raw.empty() ? std::filesystem::path(events_file_raw)
                               : state_dir / "events.jsonl";
  const std::filesystem::path error_log =
      std::filesystem::path(home) / ".claude/errors.log";

  const std::string tool_name =
      FindJsonString(request_json, "tool_name").value_or("");
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  std::string error_msg =
      FindJsonString(request_json, "tool_error")
          .value_or(FindJsonString(request_json, "error").value_or("unknown error"));

  AppendLine(error_log, "=== Tool Error ===");
  AppendLine(error_log, "Time: " + TimestampNow());
  AppendLine(error_log, "Tool: " + tool_name);
  AppendLine(error_log, "Error: " + error_msg);
  AppendLine(error_log, "PWD: " + pwd);
  AppendLine(error_log, "Git: N/A");
  AppendLine(error_log, "");

  const long ts = std::max<long>(0, UnixNow() - SessionStartSFromState(state_dir));
  if (error_msg.size() > 200) {
    error_msg.resize(200);
  }
  std::replace(error_msg.begin(), error_msg.end(), '\n', ' ');
  AppendEventLine(events_file,
                  "{\"timestamp\":" + std::to_string(ts) +
                      ",\"event_type\":\"tool_error\",\"tool\":\"" +
                      JsonEscape(tool_name) + "\",\"session_id\":\"" +
                      JsonEscape(session_id) + "\",\"error_message\":\"" +
                      JsonEscape(error_msg) + "\"}");

  RotateErrorLog(error_log);

  const std::string tool_l = Lower(tool_name);
  const std::string err_l = Lower(error_msg);
  std::vector<std::string> hints;
  if (tool_l == "bash") {
    if (err_l.find("permission denied") != std::string::npos) {
      hints.emplace_back("Hint: May need sudo or file permissions check");
    }
    if (err_l.find("command not found") != std::string::npos) {
      hints.emplace_back("Hint: Check if command is installed or PATH is set");
    }
  }
  if ((tool_l == "edit" || tool_l == "write") &&
      err_l.find("read-only") != std::string::npos) {
    hints.emplace_back("Hint: File may be read-only or in a protected directory");
  }

  if (hints.empty()) {
    return "";
  }

  std::ostringstream out;
  for (std::size_t i = 0; i < hints.size(); ++i) {
    if (i > 0) {
      out << "\n";
    }
    out << hints[i];
  }
  return out.str();
}

std::vector<RuleMetadata> ListToolErrorRules() { return {kToolErrorRule}; }

std::string EvaluateToolError(std::string_view request_json) {
  if (request_json.empty()) {
    return EvaluateToolErrorImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kToolError, request_json, "ToolError");
  const PackageMode mode = ResolveEffectiveRuleMode(kToolErrorRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateToolErrorImpl(request_json);
  const RuleAction action = response.empty() ? RuleAction::kAllow : RuleAction::kAllow;
  AppendBridgeRuleMatch(tx, kToolErrorRule, mode, action,
                        mode == PackageMode::kOn, "tool_error hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
