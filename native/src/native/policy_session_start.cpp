#include "sg/policy_session_start.hpp"

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

const RuleMetadata kSessionStartRule = {
    400100,
    "telemetry",
    "session_start_tracking",
    "",
    RulePhase::kSessionStart,
    RuleSeverity::kLow,
};

constexpr int kDefaultBudgetTotal = 280000;

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

std::string NowSns() {
  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const auto ns =
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
  const long long sec = ns / 1000000000LL;
  const long long rem = ns % 1000000000LL;
  std::ostringstream out;
  out << sec << "." << rem;
  return out.str();
}

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

int ParseInt(std::string_view raw, int fallback) {
  if (raw.empty()) {
    return fallback;
  }
  try {
    const int value = std::stoi(std::string(raw));
    if (value <= 0) {
      return fallback;
    }
    return value;
  } catch (...) {
    return fallback;
  }
}

int ReadConsumedBudget(const std::filesystem::path& budget_state) {
  const std::string raw = ReadFile(budget_state);
  return ParseInt(raw, 0);
}

std::string BudgetExportJson(int consumed, int total) {
  const int util = total > 0 ? (consumed * 100 / total) : 0;
  return "{\"consumed\":" + std::to_string(consumed) + ",\"limit\":" +
         std::to_string(total) + ",\"total_limit\":" + std::to_string(total) +
         ",\"utilization\":" + std::to_string(util) + "}";
}

}  // namespace

std::string EvaluateSessionStartImpl(std::string_view request_json) {
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  if (session_id.empty()) {
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
  const std::string session_budget_dir_raw =
      FindJsonString(request_json, "sg_session_budget_dir")
          .value_or(std::getenv("SG_SESSION_BUDGET_DIR") != nullptr
                        ? std::getenv("SG_SESSION_BUDGET_DIR")
                        : "");
  const std::string pwd =
      FindJsonString(request_json, "sg_pwd")
          .value_or(std::getenv("PWD") != nullptr ? std::getenv("PWD") : "");

  const std::filesystem::path session_times_dir =
      std::filesystem::path(home) / ".claude/.session-times";
  const std::filesystem::path state_dir =
      !state_dir_raw.empty() ? std::filesystem::path(state_dir_raw)
                             : std::filesystem::path(home) / ".claude/.statusline";
  const std::filesystem::path events_file =
      !events_file_raw.empty() ? std::filesystem::path(events_file_raw)
                               : state_dir / "events.jsonl";
  const std::filesystem::path session_budget_dir =
      !session_budget_dir_raw.empty()
          ? std::filesystem::path(session_budget_dir_raw)
          : std::filesystem::path(home) / ".claude/.session-budgets";

  WriteFile(session_times_dir / (session_id + ".start"), std::to_string(UnixNow()));
  const std::string now_sns = NowSns();
  WriteFile(session_times_dir / (session_id + ".start_ns"), now_sns);
  WriteFile(state_dir / ".session_start", now_sns);

  const std::filesystem::path budget_state_file =
      std::filesystem::path(home) / ".claude/.safeguard/budget.state";
  const int consumed = ReadConsumedBudget(budget_state_file);
  const int total = ParseInt(
      FindJsonString(request_json, "sg_budget_total")
          .value_or(std::getenv("SG_BUDGET_TOTAL") != nullptr
                        ? std::getenv("SG_BUDGET_TOTAL")
                        : ""),
      kDefaultBudgetTotal);
  WriteFile(session_budget_dir / (session_id + ".start.json"),
            BudgetExportJson(consumed, total));

  const std::filesystem::path cwd_path(pwd);
  const std::string cwd_base = cwd_path.filename().string();
  const std::string suffix = session_id.size() > 6
                                 ? session_id.substr(session_id.size() - 6)
                                 : session_id;
  const std::string session_label = cwd_base + " (" + suffix + ")";

  AppendEventLine(events_file,
                  "{\"timestamp\":0,\"event_type\":\"session_start\",\"tool\":\"SessionStart\","
                  "\"session_id\":\"" +
                      JsonEscape(session_id) + "\",\"cwd\":\"" + JsonEscape(pwd) +
                      "\",\"session_label\":\"" + JsonEscape(session_label) + "\"}");

  return "";
}

std::vector<RuleMetadata> ListSessionStartRules() { return {kSessionStartRule}; }

std::string EvaluateSessionStart(std::string_view request_json) {
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  if (session_id.empty()) {
    return EvaluateSessionStartImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kSessionStart, request_json, "SessionStart");
  const PackageMode mode = ResolveEffectiveRuleMode(kSessionStartRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluateSessionStartImpl(request_json);
  AppendBridgeRuleMatch(tx, kSessionStartRule, mode, RuleAction::kAllow,
                        mode == PackageMode::kOn, "session_start hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
