#include "sg/policy_pre_compact.hpp"

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

const RuleMetadata kPreCompactRule = {
    350100,
    "memory-defense",
    "pre_compact_memory_context",
    "",
    RulePhase::kPreCompact,
    RuleSeverity::kLow,
};

constexpr int kDefaultBudgetTotal = 280000;

std::string ReadFile(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
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

int ParseInt(std::string_view raw, int fallback) {
  if (raw.empty()) {
    return fallback;
  }
  try {
    return std::stoi(std::string(raw));
  } catch (...) {
    return fallback;
  }
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

std::string JsonPreCompact(std::string_view additional_context) {
  return "{\"hookSpecificOutput\":{\"hookEventName\":\"PreCompact\",\"additionalContext\":\"" +
         JsonEscape(additional_context) + "\"}}";
}

}  // namespace

std::string EvaluatePreCompactImpl(std::string_view request_json) {
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
  const std::string budget_total_raw =
      FindJsonString(request_json, "sg_budget_total")
          .value_or(std::getenv("SG_BUDGET_TOTAL") != nullptr
                        ? std::getenv("SG_BUDGET_TOTAL")
                        : "");

  const std::filesystem::path state_dir =
      !state_dir_raw.empty() ? std::filesystem::path(state_dir_raw)
                             : std::filesystem::path(home) / ".claude/.statusline";
  const std::filesystem::path events_file =
      !events_file_raw.empty() ? std::filesystem::path(events_file_raw)
                               : state_dir / "events.jsonl";
  const std::filesystem::path session_times_dir =
      std::filesystem::path(home) / ".claude/.session-times";
  const std::filesystem::path budget_state_file =
      std::filesystem::path(home) / ".claude/.safeguard/budget.state";

  std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  if (session_id.empty()) {
    return "";
  }

  int tool_count = 0;
  const std::string session_state = ReadFile(state_dir / ("session-" + session_id));
  if (!session_state.empty()) {
    const auto sep = session_state.find('|');
    tool_count = ParseInt(session_state.substr(0, sep), 0);
    if (tool_count < 0) {
      tool_count = 0;
    }
  }

  std::string duration_min = "unknown";
  const std::string start_raw = ReadFile(session_times_dir / (session_id + ".start"));
  if (!start_raw.empty()) {
    const long start = ParseInt(start_raw, static_cast<int>(UnixNow()));
    const long duration_sec = std::max<long>(0, UnixNow() - start);
    duration_min = std::to_string(duration_sec / 60);
  }

  int subagent_count = 0;
  const std::string subagent_count_raw = ReadFile(state_dir / "subagent-count");
  if (!subagent_count_raw.empty()) {
    std::istringstream in(subagent_count_raw);
    std::string sid;
    std::string count;
    std::getline(in, sid, '|');
    std::getline(in, count, '|');
    if (sid == session_id) {
      subagent_count = ParseInt(count, 0);
      if (subagent_count < 0) {
        subagent_count = 0;
      }
    }
  }

  const int consumed = std::max<int>(0, ParseInt(ReadFile(budget_state_file), 0));
  const int total = std::max<int>(1, ParseInt(budget_total_raw, kDefaultBudgetTotal));
  const int util = (consumed * 100) / total;

  const std::string summary =
      "[SafeGuard Session State] Tool calls: " + std::to_string(tool_count) +
      " | Duration: " + duration_min + "m | Active subagents: " +
      std::to_string(subagent_count) + " | Budget: " + std::to_string(util) + "% (" +
      std::to_string(consumed) + "/" + std::to_string(total) + ")";

  const long ts = std::max<long>(0, UnixNow() - SessionStartSFromState(state_dir));
  AppendEventLine(events_file,
                  "{\"timestamp\":" + std::to_string(ts) +
                      ",\"event_type\":\"compaction\",\"tool\":\"PreCompact\",\"session_id\":\"" +
                      JsonEscape(session_id) + "\",\"tool_count\":" +
                      std::to_string(tool_count) + "}");

  return JsonPreCompact(summary);
}

std::vector<RuleMetadata> ListPreCompactRules() { return {kPreCompactRule}; }

std::string EvaluatePreCompact(std::string_view request_json) {
  std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  if (session_id.empty()) {
    return EvaluatePreCompactImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kPreCompact, request_json, "PreCompact");
  const PackageMode mode = ResolveEffectiveRuleMode(kPreCompactRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluatePreCompactImpl(request_json);
  const RuleAction action =
      response.empty() ? RuleAction::kAllow : RuleAction::kAllow;
  AppendBridgeRuleMatch(tx, kPreCompactRule, mode, action,
                        mode == PackageMode::kOn, "pre_compact hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
