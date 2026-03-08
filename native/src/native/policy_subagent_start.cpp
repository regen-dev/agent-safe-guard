#include "sg/policy_subagent_start.hpp"

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

const RuleMetadata kSubagentStartRule = {
    150300,
    "agent-defense",
    "subagent_start_guard",
    "",
    RulePhase::kSubagentStart,
    RuleSeverity::kMedium,
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

std::string ConfigValue(const std::filesystem::path& config_path,
                        std::string_view key) {
  std::ifstream in(config_path);
  if (!in) {
    return "";
  }

  std::string line;
  while (std::getline(in, line)) {
    const auto comment = line.find('#');
    if (comment != std::string::npos) {
      line = line.substr(0, comment);
    }
    const auto eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string lhs = line.substr(0, eq);
    const std::string rhs = line.substr(eq + 1);
    if (lhs == key && !rhs.empty()) {
      return rhs;
    }
  }
  return "";
}

std::string JsonBudgetStop(int utilization, int consumed, int total) {
  return "{\"continue\": false, \"stopReason\": \"Budget exhausted (" +
         std::to_string(utilization) + "% used). " + std::to_string(consumed) +
         "/" + std::to_string(total) + " tokens.\"}";
}

std::string JsonGuidance(std::string_view text) {
  return "{\"hookSpecificOutput\":{\"hookEventName\":\"SubagentStart\",\"additionalContext\":\"" +
         JsonEscape(text) + "\"}}";
}

std::string GuidanceForType(std::string_view agent_type) {
  if (agent_type == "Explore") {
    return "Pattern: tree -> Glob -> Grep -> Read. Budget: 30 calls / 80KB output. Native tools only. BATCH: issue multiple Read/Glob/Grep calls in a single response when targets are independent. OUTPUT: max 1500 tokens. Bullet list only.";
  }
  if (agent_type == "Plan") {
    return "Pattern: structure -> patterns -> proposal. Budget: 30 calls / 80KB output. Read-only. BATCH: issue multiple Read calls in a single response. OUTPUT: max 2000 tokens. Numbered implementation steps only.";
  }
  if (agent_type == "general-purpose") {
    return "Pattern: explore -> plan -> execute. Budget: 35 calls / 120KB output. BATCH: issue multiple independent tool calls in a single response. OUTPUT: max 2000 tokens. Concise results only.";
  }
  if (agent_type == "code-reviewer" || agent_type == "security-auditor") {
    return "Pattern: scope -> grep -> read. Budget: 25-30 calls / 100KB output. Read-only. BATCH: after scoping files, Read ALL target files in a single response. OUTPUT: max 2000 tokens. Bullet findings with file:line refs.";
  }
  if (agent_type == "deep-debugger") {
    return "Pattern: reproduce -> narrow -> instrument. Budget: 40 calls / 150KB output. BATCH: issue multiple Read/Grep calls in a single response. OUTPUT: max 2000 tokens. Root cause + evidence only.";
  }
  if (agent_type == "refactor" || agent_type == "architect" ||
      agent_type == "strategist" || agent_type == "nix-expert" ||
      agent_type == "git-ops" || agent_type == "test-runner") {
    return "Follow agent-specific workflow. Budget: 25-35 calls / 100-120KB output. BATCH: issue multiple independent tool calls in a single response. OUTPUT: max 2000 tokens.";
  }
  return "";
}

}  // namespace

std::string EvaluateSubagentStartImpl(std::string_view request_json) {
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
  const std::filesystem::path config_file =
      std::filesystem::path(home) / ".claude/.safeguard/config.env";

  std::string agent_id =
      SanitizeId(FindJsonString(request_json, "agent_id").value_or("unknown"));
  if (agent_id.empty()) {
    agent_id = "unknown";
  }
  const std::string agent_type =
      FindJsonString(request_json, "agent_type").value_or("");
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));

  std::error_code ec;
  std::filesystem::create_directories(subagent_state_dir, ec);
  std::filesystem::create_directories(state_dir, ec);
  const long epoch = UnixNow();

  const int consumed = std::max<int>(0, ParseInt(ReadFile(budget_state_file), 0));
  std::string budget_total_raw =
      FindJsonString(request_json, "sg_budget_total").value_or("");
  if (budget_total_raw.empty()) {
    budget_total_raw = ConfigValue(config_file, "SG_BUDGET_TOTAL");
  }
  const int budget_total =
      std::max<int>(1, ParseInt(budget_total_raw, kDefaultBudgetTotal));

  if (consumed >= budget_total) {
    const int util = (consumed * 100) / budget_total;
    return JsonBudgetStop(util, consumed, budget_total);
  }

  const int util = (consumed * 100) / budget_total;
  const std::filesystem::path alert_file = state_dir / "budget-alert";
  if (util >= 90) {
    WriteFile(alert_file, "CRITICAL|" + std::to_string(util) + "|" +
                            std::to_string(epoch) + "\n");
  } else if (util >= 75) {
    const std::string alert_raw = ReadFile(alert_file);
    const auto sep = alert_raw.find('|');
    const std::string prev_level = sep == std::string::npos
                                       ? alert_raw
                                       : alert_raw.substr(0, sep);
    if (prev_level != "WARNING" && prev_level != "CRITICAL") {
      WriteFile(alert_file, "WARNING|" + std::to_string(util) + "|" +
                              std::to_string(epoch) + "\n");
    }
  }

  WriteFile(subagent_state_dir / (agent_id + ".start"), std::to_string(epoch));
  if (!session_id.empty()) {
    WriteFile(subagent_state_dir / ("session-" + session_id), agent_id + "\n");
  }
  WriteFile(subagent_state_dir / agent_id,
            "AGENT_TYPE=" + agent_type + "\nSESSION_ID=" + session_id + "\n");

  const long ts = std::max<long>(0, UnixNow() - SessionStartSFromState(state_dir));
  AppendEventLine(events_file,
                  "{\"timestamp\":" + std::to_string(ts) +
                      ",\"event_type\":\"subagent_start\",\"tool\":\"SubagentStart\","
                      "\"session_id\":\"" +
                      JsonEscape(session_id) + "\",\"agent_id\":\"" +
                      JsonEscape(agent_id) + "\",\"agent_type\":\"" +
                      JsonEscape(agent_type) + "\"}");

  if (!session_id.empty()) {
    int prev_count = 0;
    const std::filesystem::path count_file = state_dir / "subagent-count";
    const std::string count_raw = ReadFile(count_file);
    if (!count_raw.empty()) {
      std::istringstream in(count_raw);
      std::string prev_session;
      std::string count_field;
      std::getline(in, prev_session, '|');
      std::getline(in, count_field, '|');
      if (prev_session == session_id) {
        prev_count = std::max<int>(0, ParseInt(count_field, 0));
      }
    }
    WriteFile(count_file, session_id + "|" + std::to_string(prev_count + 1) + "|" +
                            std::to_string(epoch) + "\n");
  }

  const std::string guidance = GuidanceForType(agent_type);
  if (!guidance.empty()) {
    return JsonGuidance(guidance);
  }
  return "";
}

std::vector<RuleMetadata> ListSubagentStartRules() {
  return {kSubagentStartRule};
}

std::string EvaluateSubagentStart(std::string_view request_json) {
  if (request_json.empty()) {
    return EvaluateSubagentStartImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kSubagentStart, request_json, "SubagentStart");
  const PackageMode mode = ResolveEffectiveRuleMode(kSubagentStartRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateSubagentStartImpl(request_json);
  const RuleAction action = InferBridgeAction(response, RuleAction::kAllow);
  AppendBridgeRuleMatch(tx, kSubagentStartRule, mode, action,
                        mode == PackageMode::kOn,
                        "subagent_start hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
