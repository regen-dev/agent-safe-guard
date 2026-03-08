#include "sg/policy_session_end.hpp"

#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_bridge.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

namespace sg {
namespace {

const RuleMetadata kSessionEndRule = {
    400110,
    "telemetry",
    "session_end_cleanup",
    "",
    RulePhase::kSessionEnd,
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

std::string TimestampNow() {
  const std::time_t now = std::time(nullptr);
  std::tm tm{};
  localtime_r(&now, &tm);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);
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

void RemoveIfExists(const std::filesystem::path& path) {
  std::error_code ec;
  std::filesystem::remove(path, ec);
}

}  // namespace

std::string EvaluateSessionEndImpl(std::string_view request_json) {
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
  const std::string subagent_state_dir_raw =
      FindJsonString(request_json, "sg_subagent_state_dir")
          .value_or(std::getenv("SG_SUBAGENT_STATE_DIR") != nullptr
                        ? std::getenv("SG_SUBAGENT_STATE_DIR")
                        : "");
  const std::string session_budget_dir_raw =
      FindJsonString(request_json, "sg_session_budget_dir")
          .value_or(std::getenv("SG_SESSION_BUDGET_DIR") != nullptr
                        ? std::getenv("SG_SESSION_BUDGET_DIR")
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
  const std::filesystem::path subagent_state_dir =
      !subagent_state_dir_raw.empty()
          ? std::filesystem::path(subagent_state_dir_raw)
          : std::filesystem::path(home) / ".claude/.subagent-state";
  const std::filesystem::path session_budget_dir =
      !session_budget_dir_raw.empty()
          ? std::filesystem::path(session_budget_dir_raw)
          : std::filesystem::path(home) / ".claude/.session-budgets";
  const std::filesystem::path session_times_dir =
      std::filesystem::path(home) / ".claude/.session-times";
  const std::filesystem::path log_file =
      std::filesystem::path(home) / ".claude/session-log.txt";
  const std::filesystem::path reset_reason_file = state_dir / "reset-reason";

  std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or("unknown"));
  if (session_id.empty()) {
    session_id = "unknown";
  }
  const std::string reason =
      FindJsonString(request_json, "reason").value_or("");

  std::string duration_min = "unknown";
  const std::filesystem::path session_start_file =
      session_times_dir / (session_id + ".start");
  if (std::filesystem::is_regular_file(session_start_file)) {
    try {
      const long start_epoch = std::stol(ReadFile(session_start_file));
      const long duration = std::max<long>(0, UnixNow() - start_epoch);
      duration_min = std::to_string(duration / 60);
      const long ts = std::max<long>(0, UnixNow() - SessionStartSFromState(state_dir));
      AppendEventLine(events_file,
                      "{\"timestamp\":" + std::to_string(ts) +
                          ",\"event_type\":\"session_end\",\"tool\":\"SessionEnd\",\"session_id\":\"" +
                          JsonEscape(session_id) + "\",\"duration_seconds\":" +
                          std::to_string(duration) + "}");
      RemoveIfExists(session_budget_dir / (session_id + ".start.json"));
    } catch (...) {
      duration_min = "unknown";
    }
  }

  if (std::filesystem::is_directory(subagent_state_dir)) {
    for (const auto& entry : std::filesystem::directory_iterator(subagent_state_dir)) {
      if (!entry.is_regular_file()) {
        continue;
      }
      const std::string name = entry.path().filename().string();
      if (name.find('.') != std::string::npos) {
        continue;
      }
      const std::string content = ReadFile(entry.path());
      if (content.find("SESSION_ID=" + session_id) == std::string::npos) {
        continue;
      }
      RemoveIfExists(entry.path());
      RemoveIfExists(entry.path().string() + ".start");
    }
  }

  AppendLine(log_file,
             "[" + TimestampNow() + "] Session ended: " + session_id +
                 " (duration: " + duration_min + "m, dir: " + pwd +
                 ", reason: " + reason + ")");

  if (!reason.empty()) {
    WriteFile(reset_reason_file,
              std::to_string(UnixNow()) + "|" + reason + "|" + session_id + "\n");
  }

  return "";
}

std::vector<RuleMetadata> ListSessionEndRules() { return {kSessionEndRule}; }

std::string EvaluateSessionEnd(std::string_view request_json) {
  if (request_json.empty()) {
    return EvaluateSessionEndImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kSessionEnd, request_json, "SessionEnd");
  const PackageMode mode = ResolveEffectiveRuleMode(kSessionEndRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateSessionEndImpl(request_json);
  AppendBridgeRuleMatch(tx, kSessionEndRule, mode, RuleAction::kAllow,
                        mode == PackageMode::kOn, "session_end hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
