#include "sg/policy_stop.hpp"

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
#include <iomanip>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>

namespace sg {
namespace {

const RuleMetadata kStopRule = {
    400120,
    "telemetry",
    "stop_summary_emit",
    "",
    RulePhase::kStop,
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

void AppendLine(const std::filesystem::path& path, const std::string& line) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::app);
  if (!out) {
    return;
  }
  out << line << "\n";
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

std::string TimestampNow() {
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
  localtime_r(&now, &tm);
  std::ostringstream out;
  out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
  return out.str();
}

long SessionStartSFromState(const std::filesystem::path& state_dir) {
  const std::string raw = ReadFile(state_dir / ".session_start");
  if (raw.empty()) {
    return UnixNow();
  }
  const auto dot = raw.find('.');
  const std::string trimmed = raw.substr(0, dot);
  try {
    return std::stol(trimmed);
  } catch (...) {
    return UnixNow();
  }
}

bool StopHookActive(std::string_view json) {
  static const std::regex kRx(R"("stop_hook_active"\s*:\s*true)");
  return std::regex_search(std::string(json), kRx);
}

int CountBlockedEvents(const std::filesystem::path& events_file) {
  std::ifstream in(events_file);
  if (!in) {
    return 0;
  }
  std::string line;
  int legacy_count = 0;
  int rule_count = 0;
  while (std::getline(in, line)) {
    if (line.find("\"event_type\":\"rule_match\"") != std::string::npos &&
        line.find("\"disposition\":\"blocked\"") != std::string::npos) {
      ++rule_count;
      continue;
    }
    if (line.find("\"event_type\":\"blocked\"") != std::string::npos) {
      ++legacy_count;
    }
  }
  return rule_count > 0 ? rule_count : legacy_count;
}

std::string JsonSummary(std::string_view text) {
  return "{\"stop_hook_summary\":\"" + JsonEscape(text) + "\"}";
}

}  // namespace

std::string EvaluateStopImpl(std::string_view request_json) {
  if (StopHookActive(request_json)) {
    return "";
  }

  const std::string reason =
      FindJsonString(request_json, "reason").value_or("unknown");
  const std::string tool_name =
      FindJsonString(request_json, "tool_name").value_or("");
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));

  const std::string home =
      FindJsonString(request_json, "sg_home")
          .value_or(std::getenv("HOME") != nullptr ? std::getenv("HOME") : "");
  const std::string state_dir_raw =
      FindJsonString(request_json, "sg_state_dir")
          .value_or(std::getenv("SG_STATE_DIR") != nullptr
                        ? std::getenv("SG_STATE_DIR")
                        : "");
  const std::filesystem::path state_dir =
      !state_dir_raw.empty() ? std::filesystem::path(state_dir_raw)
                             : std::filesystem::path(home) / ".claude/.statusline";

  const std::string events_file_raw =
      FindJsonString(request_json, "sg_events_file")
          .value_or(std::getenv("SG_EVENTS_FILE") != nullptr
                        ? std::getenv("SG_EVENTS_FILE")
                        : "");
  const std::filesystem::path events_file =
      !events_file_raw.empty() ? std::filesystem::path(events_file_raw)
                               : state_dir / "events.jsonl";
  const std::filesystem::path log_file =
      std::filesystem::path(home) / ".claude/session-log.txt";
  const std::filesystem::path session_start_file =
      std::filesystem::path(home) / ".claude/.session-times" /
      (session_id + ".start");

  std::string duration = "unknown";
  long duration_secs = 0;
  if (!session_id.empty()) {
    const std::string start_raw = ReadFile(session_start_file);
    if (!start_raw.empty()) {
      try {
        const long start_epoch = std::stol(start_raw);
        duration_secs = std::max<long>(0, UnixNow() - start_epoch);
        duration = std::to_string(duration_secs) + "s";
      } catch (...) {
        duration = "unknown";
      }
    }
  }

  const std::string timestamp = TimestampNow();
  if (!tool_name.empty()) {
    AppendLine(log_file, "[" + timestamp + "] Stop: " + reason + " (tool: " +
                         tool_name + ", duration: " + duration + ")");
  } else {
    AppendLine(log_file, "[" + timestamp + "] Stop: " + reason +
                         " (duration: " + duration + ")");
  }

  const long ts =
      std::max<long>(0, UnixNow() - SessionStartSFromState(state_dir));
  AppendEventLine(events_file,
                  "{\"timestamp\":" + std::to_string(ts) +
                      ",\"event_type\":\"session_stop\",\"tool\":\"Stop\",\"session_id\":\"" +
                      JsonEscape(session_id) + "\",\"reason\":\"" + JsonEscape(reason) +
                      "\",\"duration_seconds\":" + std::to_string(duration_secs) + "}");

  const int blocked = CountBlockedEvents(events_file);
  const std::string summary = "Session: " + std::to_string(duration_secs) +
                              "s | blocks: " + std::to_string(blocked) +
                              " | reason: " + reason;
  return JsonSummary(summary);
}

std::vector<RuleMetadata> ListStopRules() { return {kStopRule}; }

std::string EvaluateStop(std::string_view request_json) {
  if (StopHookActive(request_json) || request_json.empty()) {
    return EvaluateStopImpl(request_json);
  }

  const Transaction tx = BuildBridgeTransaction(RulePhase::kStop, request_json, "Stop");
  const PackageMode mode = ResolveEffectiveRuleMode(kStopRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateStopImpl(request_json);
  AppendBridgeRuleMatch(tx, kStopRule, mode, RuleAction::kAllow,
                        mode == PackageMode::kOn, "stop hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
