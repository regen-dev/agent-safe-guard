#include "sg/policy_subagent_stop.hpp"

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

const RuleMetadata kSubagentStopRule = {
    150310,
    "agent-defense",
    "subagent_stop_reclaim",
    "",
    RulePhase::kSubagentStop,
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

std::string AgentTypeFromState(const std::filesystem::path& agent_state_file) {
  const std::string raw = ReadFile(agent_state_file);
  if (raw.empty()) {
    return "unknown";
  }
  std::istringstream in(raw);
  std::string line;
  while (std::getline(in, line)) {
    constexpr std::string_view kPrefix = "AGENT_TYPE=";
    if (line.rfind(kPrefix.data(), 0) == 0) {
      return line.substr(kPrefix.size());
    }
  }
  return "unknown";
}

}  // namespace

std::string EvaluateSubagentStopImpl(std::string_view request_json) {
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
  const std::filesystem::path budget_state_file =
      std::filesystem::path(home) / ".claude/.safeguard/budget.state";
  const std::filesystem::path subagent_count_file = state_dir / "subagent-count";

  std::string agent_id =
      SanitizeId(FindJsonString(request_json, "agent_id").value_or("unknown"));
  if (agent_id.empty()) {
    agent_id = "unknown";
  }
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  const std::string worktree_path =
      FindJsonString(request_json, "worktree_path").value_or("");

  const std::filesystem::path byte_file = subagent_state_dir / (agent_id + ".bytes");
  const std::string byte_raw = ReadFile(byte_file);
  if (!byte_raw.empty()) {
    const auto sep = byte_raw.find('|');
    const int total_bytes =
        std::max<int>(0, ParseInt(byte_raw.substr(0, sep), 0));
    if (total_bytes > 0) {
      const int consumed_tokens = (total_bytes * 10) / 35;
      const int prev_budget = std::max<int>(0, ParseInt(ReadFile(budget_state_file), 0));
      WriteFile(budget_state_file,
                std::to_string(prev_budget + consumed_tokens) + "\n");
    }
  }

  const std::filesystem::path start_file = subagent_state_dir / (agent_id + ".start");
  const std::string start_raw = ReadFile(start_file);
  if (!start_raw.empty()) {
    const int start_time = ParseInt(start_raw, static_cast<int>(UnixNow()));
    const int duration = std::max<int>(0, static_cast<int>(UnixNow()) - start_time);
    const std::string agent_type = AgentTypeFromState(subagent_state_dir / agent_id);
    const long ts = std::max<long>(0, UnixNow() - SessionStartSFromState(state_dir));
    const std::string has_worktree = worktree_path.empty() ? "false" : "true";

    AppendEventLine(events_file,
                    "{\"timestamp\":" + std::to_string(ts) +
                        ",\"event_type\":\"subagent_stop\",\"tool\":\"SubagentStop\","
                        "\"session_id\":\"" +
                        JsonEscape(session_id) + "\",\"agent_id\":\"" +
                        JsonEscape(agent_id) + "\",\"agent_type\":\"" +
                        JsonEscape(agent_type) + "\",\"duration_seconds\":" +
                        std::to_string(duration) + ",\"has_worktree\":" + has_worktree +
                        "}");
  }

  if (!session_id.empty()) {
    const std::string count_raw = ReadFile(subagent_count_file);
    if (!count_raw.empty()) {
      std::istringstream in(count_raw);
      std::string prev_session;
      std::string prev_count_raw;
      std::getline(in, prev_session, '|');
      std::getline(in, prev_count_raw, '|');
      if (prev_session == session_id) {
        int prev_count = std::max<int>(0, ParseInt(prev_count_raw, 0));
        if (prev_count > 0) {
          --prev_count;
        }
        WriteFile(subagent_count_file,
                  session_id + "|" + std::to_string(prev_count) + "|" +
                      std::to_string(UnixNow()) + "\n");
      }
    }
  }

  return "";
}

std::vector<RuleMetadata> ListSubagentStopRules() {
  return {kSubagentStopRule};
}

std::string EvaluateSubagentStop(std::string_view request_json) {
  if (request_json.empty()) {
    return EvaluateSubagentStopImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kSubagentStop, request_json, "SubagentStop");
  const PackageMode mode = ResolveEffectiveRuleMode(kSubagentStopRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateSubagentStopImpl(request_json);
  AppendBridgeRuleMatch(tx, kSubagentStopRule, mode, RuleAction::kAllow,
                        mode == PackageMode::kOn,
                        "subagent_stop hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
