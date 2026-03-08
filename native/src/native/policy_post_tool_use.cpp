#include "sg/policy_post_tool_use.hpp"

#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_bridge.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace sg {
namespace {

const RuleMetadata kPostToolUseRule = {
    250100,
    "output-defense",
    "post_tool_use_pipeline",
    "",
    RulePhase::kPostToolUse,
    RuleSeverity::kMedium,
};

constexpr int kDefaultTruncateBytes = 20480;
constexpr int kDefaultSubagentReadBytes = 10240;
constexpr int kDefaultSuppressBytes = 524288;
constexpr int kDefaultBudgetTotal = 280000;

struct Config {
  int truncate_bytes = kDefaultTruncateBytes;
  int subagent_read_bytes = kDefaultSubagentReadBytes;
  int suppress_bytes = kDefaultSuppressBytes;
  int budget_total = kDefaultBudgetTotal;
  std::filesystem::path state_dir = "/tmp/.sg-state";
  std::filesystem::path subagent_state_dir = "/tmp/.sg-subagent-state";
  std::filesystem::path events_file = "/tmp/.sg-events.jsonl";
  std::filesystem::path budget_state_file = "/tmp/.sg-budget.state";
};

long UnixNow() {
  return static_cast<long>(std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now()));
}

long long NowNs() {
  return static_cast<long long>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string Trim(std::string_view input) {
  std::size_t first = 0;
  while (first < input.size() && std::isspace(static_cast<unsigned char>(input[first])) != 0) {
    ++first;
  }
  std::size_t last = input.size();
  while (last > first && std::isspace(static_cast<unsigned char>(input[last - 1])) != 0) {
    --last;
  }
  return std::string(input.substr(first, last - first));
}

int ParseInt(const std::string& value, int fallback) {
  const std::string t = Trim(value);
  if (t.empty()) {
    return fallback;
  }
  char* end = nullptr;
  const long v = std::strtol(t.c_str(), &end, 10);
  if (end == t.c_str() || *end != '\0') {
    return fallback;
  }
  if (v < 0 || v > std::numeric_limits<int>::max()) {
    return fallback;
  }
  return static_cast<int>(v);
}

std::string SanitizeId(const std::string& id) {
  std::string out;
  for (const unsigned char ch : id) {
    if (std::isalnum(ch) != 0 || ch == '_' || ch == '-') {
      out.push_back(static_cast<char>(ch));
    }
  }
  return out;
}

std::string ReadFile(const std::filesystem::path& p) {
  std::ifstream in(p, std::ios::binary);
  if (!in) {
    return "";
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

bool WriteFile(const std::filesystem::path& p, const std::string& s) {
  std::ofstream out(p, std::ios::trunc | std::ios::binary);
  if (!out) {
    return false;
  }
  out << s;
  return static_cast<bool>(out);
}

void AppendEvent(const Config& cfg, std::string_view event_json) {
  AppendEventLine(cfg.events_file, event_json);
}

std::string JsonSuppress() { return "{\"suppressOutput\":true}"; }

std::string JsonModify(std::string_view text) {
  return "{\"modifyOutput\":\"" + JsonEscape(text) + "\"}";
}

bool IsSubagent(const std::string& transcript_path) {
  return transcript_path.find("/subagents/") != std::string::npos ||
         transcript_path.find("/tmp/") != std::string::npos;
}

std::string AgentId(const std::string& transcript_path) {
  if (transcript_path.find("/subagents/") == std::string::npos) {
    return "";
  }
  std::filesystem::path p(transcript_path);
  std::string base = p.filename().string();
  if (base.size() > 6 && base.substr(base.size() - 6) == ".jsonl") {
    base.resize(base.size() - 6);
  }
  if (base.rfind("agent-", 0) == 0) {
    base.erase(0, 6);
  }
  return SanitizeId(base);
}

Config LoadConfig(std::string_view json) {
  Config cfg;
  auto set_int = [&](const char* field, int* out, int fallback) {
    const auto v = FindJsonString(json, field);
    if (v.has_value()) {
      *out = ParseInt(*v, fallback);
    }
  };

  set_int("sg_truncate_bytes", &cfg.truncate_bytes, cfg.truncate_bytes);
  set_int("sg_subagent_read_bytes", &cfg.subagent_read_bytes,
          cfg.subagent_read_bytes);
  set_int("sg_suppress_bytes", &cfg.suppress_bytes, cfg.suppress_bytes);
  set_int("sg_budget_total", &cfg.budget_total, cfg.budget_total);

  if (const auto v = FindJsonString(json, "sg_state_dir"); v.has_value() && !v->empty()) {
    cfg.state_dir = *v;
  }
  if (const auto v = FindJsonString(json, "sg_subagent_state_dir"); v.has_value() &&
                                                               !v->empty()) {
    cfg.subagent_state_dir = *v;
  }
  if (const auto v = FindJsonString(json, "sg_events_file"); v.has_value() && !v->empty()) {
    cfg.events_file = *v;
  }
  if (const auto v = FindJsonString(json, "sg_budget_state_file"); v.has_value() &&
                                                              !v->empty()) {
    cfg.budget_state_file = *v;
  }

  if (cfg.truncate_bytes > cfg.suppress_bytes) {
    cfg.truncate_bytes = cfg.suppress_bytes;
  }
  return cfg;
}

std::string FirstNonEmpty(std::initializer_list<std::optional<std::string>> vals) {
  for (const auto& v : vals) {
    if (v.has_value() && !v->empty()) {
      return *v;
    }
  }
  return "";
}

std::string TrimTrailingBlankLines(const std::string& s) {
  std::vector<std::string> lines;
  std::string line;
  std::istringstream in(s);
  while (std::getline(in, line)) {
    lines.push_back(line);
  }
  while (!lines.empty() && Trim(lines.back()).empty()) {
    lines.pop_back();
  }
  std::ostringstream out;
  for (std::size_t i = 0; i < lines.size(); ++i) {
    if (i > 0) {
      out << '\n';
    }
    out << lines[i];
  }
  return out.str();
}

std::string StripSystemReminder(const std::string& input) {
  std::istringstream in(input);
  std::ostringstream out;
  std::string line;
  bool skipping = false;
  bool first = true;
  while (std::getline(in, line)) {
    if (line == "<system-reminder>") {
      skipping = true;
      continue;
    }
    if (line == "</system-reminder>") {
      skipping = false;
      continue;
    }
    if (skipping) {
      continue;
    }
    if (!first) {
      out << '\n';
    }
    out << line;
    first = false;
  }
  return TrimTrailingBlankLines(out.str());
}

std::string StripGitHints(const std::string& input) {
  std::istringstream in(input);
  std::ostringstream out;
  std::string line;
  bool first = true;
  while (std::getline(in, line)) {
    if (line.rfind("hint: ", 0) == 0) {
      continue;
    }
    if (!first) {
      out << '\n';
    }
    out << line;
    first = false;
  }
  return out.str();
}

void TrackSessionState(const Config& cfg, const std::string& session_id,
                       const std::string& tool_name, const std::string& command,
                       int output_size) {
  if (session_id.empty()) {
    return;
  }

  std::error_code ec;
  std::filesystem::create_directories(cfg.state_dir, ec);
  const std::filesystem::path state_file = cfg.state_dir / ("session-" + session_id);

  int prev_count = 0;
  int prev_bytes = 0;
  std::string prev_label;
  if (std::filesystem::exists(state_file, ec)) {
    std::string content = ReadFile(state_file);
    std::vector<std::string> parts;
    std::istringstream is(content);
    std::string part;
    while (std::getline(is, part, '|')) {
      parts.push_back(part);
    }
    if (parts.size() >= 4) {
      prev_count = ParseInt(parts[0], 0);
      prev_bytes = ParseInt(parts[1], 0);
      prev_label = parts[2];
    }
  }

  int new_count = prev_count + 1;
  int top_bytes = prev_bytes;
  std::string top_label = prev_label;

  if (output_size > prev_bytes) {
    top_bytes = output_size;
    if (tool_name == "Bash" && !command.empty()) {
      std::string trimmed = Trim(command);
      auto pos = trimmed.find_first_of(" \t\n");
      top_label = "Bash:" + (pos == std::string::npos ? trimmed : trimmed.substr(0, pos));
    } else {
      top_label = tool_name;
    }
  }
  std::replace(top_label.begin(), top_label.end(), '|', '_');

  (void)WriteFile(state_file, std::to_string(new_count) + "|" + std::to_string(top_bytes) +
                                "|" + top_label + "|" + std::to_string(UnixNow()) + "\n");

  if (new_count % 50 != 0) {
    return;
  }

  int consumed = ParseInt(ReadFile(cfg.budget_state_file), 0);
  if (cfg.budget_total <= 0) {
    return;
  }
  int util = (consumed * 100) / cfg.budget_total;
  const std::filesystem::path alert_file = cfg.state_dir / "budget-alert";
  if (util >= 90) {
    (void)WriteFile(alert_file, "CRITICAL|" + std::to_string(util) + "|" +
                                std::to_string(UnixNow()) + "\n");
    return;
  }
  if (util >= 75) {
    std::string prev = ReadFile(alert_file);
    std::string prev_level;
    auto pos = prev.find('|');
    if (pos != std::string::npos) {
      prev_level = prev.substr(0, pos);
    }
    if (prev_level != "WARNING" && prev_level != "CRITICAL") {
      (void)WriteFile(alert_file, "WARNING|" + std::to_string(util) + "|" +
                                  std::to_string(UnixNow()) + "\n");
    }
  }
}

void TrackSubagentBytes(const Config& cfg, bool is_subagent, const std::string& agent_id,
                        const std::string& tool_name, int output_size) {
  if (!is_subagent || agent_id.empty()) {
    return;
  }
  std::error_code ec;
  std::filesystem::create_directories(cfg.subagent_state_dir, ec);
  const std::filesystem::path byte_file = cfg.subagent_state_dir / (agent_id + ".bytes");

  int prev = 0;
  std::string raw = ReadFile(byte_file);
  if (!raw.empty()) {
    auto pipe = raw.find('|');
    if (pipe != std::string::npos) {
      prev = ParseInt(raw.substr(0, pipe), 0);
    }
  }

  int now = prev + output_size;
  (void)WriteFile(byte_file, std::to_string(now) + "|" + tool_name + "|" +
                               std::to_string(UnixNow()) + "\n");
}

void EmitLatencyIfAny(const Config& cfg, const std::string& tool_name,
                      const std::string& session_id,
                      const std::string& command) {
  if (tool_name.empty()) {
    return;
  }
  std::error_code ec;
  std::filesystem::create_directories(cfg.state_dir, ec);

  std::filesystem::path newest;
  std::filesystem::file_time_type newest_time;
  bool found = false;

  const std::string prefix = ".tool-start-" + tool_name + "-";
  for (const auto& entry : std::filesystem::directory_iterator(cfg.state_dir, ec)) {
    if (!entry.is_regular_file()) {
      continue;
    }
    const std::string name = entry.path().filename().string();
    if (name.rfind(prefix, 0) != 0) {
      continue;
    }
    auto t = entry.last_write_time(ec);
    if (!found || t > newest_time) {
      newest = entry.path();
      newest_time = t;
      found = true;
    }
  }

  if (!found) {
    return;
  }

  long long start_ns = 0;
  {
    std::string raw = ReadFile(newest);
    start_ns = std::strtoll(raw.c_str(), nullptr, 10);
  }
  std::filesystem::remove(newest, ec);
  if (start_ns <= 0) {
    return;
  }

  long long end_ns = NowNs();
  long long delta_ns = end_ns - start_ns;
  long long ms = delta_ns / 1000000;
  if (ms < 0 || ms > 600000) {
    return;
  }

  std::ostringstream ev;
  ev << "{\"timestamp\":" << UnixNow() << ",\"event_type\":\"tool_latency\","
     << "\"tool\":\"" << JsonEscape(tool_name) << "\","
     << "\"session_id\":\"" << JsonEscape(session_id) << "\","
     << "\"duration_ms\":" << ms << ","
     << "\"original_cmd\":\"" << JsonEscape(command.substr(0, 200)) << "\"}";
  AppendEvent(cfg, ev.str());
}

bool HasNul(const std::string& s) {
  return std::find(s.begin(), s.end(), '\0') != s.end();
}

std::string BuildTaskStructured(const std::string& output) {
  std::istringstream in(output);
  std::ostringstream out;
  std::string line;
  int kept = 0;
  while (std::getline(in, line)) {
    bool keep = false;
    if (std::regex_search(line, std::regex(R"(^[-*] )"))) keep = true;
    if (std::regex_search(line, std::regex(R"(^[0-9]+[.)])"))) keep = true;
    if (std::regex_search(line, std::regex(R"(^#{1,4} )"))) keep = true;
    if (std::regex_search(line, std::regex(R"(^[|])"))) keep = true;
    if (std::regex_search(line, std::regex(R"(^[[:space:]]*[-*] )"))) keep = true;
    if (std::regex_search(line, std::regex(R"(^[a-zA-Z_.\/ ]*\.[a-z]{1,4}:[0-9])"))) keep = true;
    if (!keep) continue;
    out << line << '\n';
    ++kept;
    if (kept >= 120) break;
  }
  return TrimTrailingBlankLines(out.str());
}

}  // namespace

std::string EvaluatePostToolUseImpl(std::string_view request_json) {
  const Config cfg = LoadConfig(request_json);

  const std::string tool_name = FindJsonString(request_json, "tool_name").value_or("");
  const std::string session_id =
      SanitizeId(FindJsonString(request_json, "session_id").value_or(""));
  const std::string transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");

  std::string command = FirstNonEmpty({FindJsonString(request_json, "command"),
                                       FindJsonString(request_json, "file_path"),
                                       FindJsonString(request_json, "pattern"),
                                       FindJsonString(request_json, "prompt")});
  if (command.size() > 200) {
    command.resize(200);
  }

  std::string output = FindJsonString(request_json, "text").value_or("");
  int output_size = static_cast<int>(output.size());

  const bool is_subagent = IsSubagent(transcript_path);
  const std::string agent_id = AgentId(transcript_path);

  TrackSessionState(cfg, session_id, tool_name, command, output_size);
  TrackSubagentBytes(cfg, is_subagent, agent_id, tool_name, output_size);
  EmitLatencyIfAny(cfg, tool_name, session_id, command);

  bool reminder_pre_stripped = false;
  if (output_size > 50 && output.find("<system-reminder>") != std::string::npos) {
    const std::string cleaned = StripSystemReminder(output);
    if (cleaned.size() < output.size()) {
      if (tool_name == "Bash" || tool_name == "Grep" || tool_name == "Glob" ||
          tool_name == "Task") {
        output = cleaned;
        output_size = static_cast<int>(output.size());
        reminder_pre_stripped = true;
      } else {
        return JsonModify(cleaned);
      }
    }
  }

  if (tool_name == "Bash" && output.find("hint: ") != std::string::npos) {
    const std::string cleaned = StripGitHints(output);
    if (cleaned.size() < output.size()) {
      output = cleaned;
      output_size = static_cast<int>(output.size());
      reminder_pre_stripped = true;
    }
  }

  auto exit_clean_or_suppress = [&]() {
    if (reminder_pre_stripped) {
      return JsonModify(output);
    }
    return JsonSuppress();
  };

  if (!(tool_name == "Bash" || tool_name == "Grep" || tool_name == "Glob" ||
        tool_name == "Task" || tool_name == "Read")) {
    return JsonSuppress();
  }

  if (tool_name == "Read" && !is_subagent) {
    return JsonSuppress();
  }

  if (tool_name == "Task" && output_size > 6144) {
    std::string structured = BuildTaskStructured(output);
    int struct_size = static_cast<int>(structured.size());
    if (struct_size > 200 && struct_size < output_size) {
      std::ostringstream msg;
      msg << structured << "\n\n[Agent output compressed: " << (output_size / 1024)
          << "KB -> " << (struct_size / 1024) << "KB structured lines]";
      return JsonModify(msg.str());
    }
  }

  int threshold = cfg.truncate_bytes;
  if (is_subagent && tool_name == "Read") {
    threshold = cfg.subagent_read_bytes;
  }
  if (threshold > cfg.suppress_bytes) {
    threshold = cfg.suppress_bytes;
  }

  if (output_size <= threshold) {
    return exit_clean_or_suppress();
  }

  if (HasNul(output)) {
    std::ostringstream msg;
    msg << "[Binary output: " << (output_size / 1024)
        << "KB. Use 'file' or redirect.]";
    return JsonModify(msg.str());
  }

  if (output_size > cfg.suppress_bytes) {
    std::ostringstream msg;
    msg << "[Output too large: " << (output_size / 1048576)
        << "MB. Use | head or redirect.]";
    return JsonModify(msg.str());
  }

  std::string head = output.substr(0, std::min<std::size_t>(8000, output.size()));
  const std::string cmd_l = command;
  if (cmd_l.find("nm ") != std::string::npos || cmd_l.find(" nm") != std::string::npos ||
      cmd_l.find("strings ") != std::string::npos || cmd_l.find("otool") != std::string::npos ||
      cmd_l.find("jtool") != std::string::npos || cmd_l.find("class-dump") != std::string::npos) {
    return JsonModify(head);
  }

  std::string tail = output.size() > 2000 ? output.substr(output.size() - 2000) : output;
  std::ostringstream final;
  final << head << "\n... [" << (output_size / 1024) << "KB truncated to 10KB] ...\n" << tail;
  return JsonModify(final.str());
}

std::vector<RuleMetadata> ListPostToolUseRules() { return {kPostToolUseRule}; }

std::string EvaluatePostToolUse(std::string_view request_json) {
  if (request_json.empty()) {
    return EvaluatePostToolUseImpl(request_json);
  }

  const Transaction tx =
      BuildBridgeTransaction(RulePhase::kPostToolUse, request_json, "PostToolUse");
  const PackageMode mode = ResolveEffectiveRuleMode(kPostToolUseRule);
  if (mode == PackageMode::kOff) {
    return PassthroughResponse();
  }

  const std::string response = EvaluatePostToolUseImpl(request_json);
  const RuleAction action = InferBridgeAction(
      response, response.empty() ? RuleAction::kAllow : RuleAction::kAllow);
  AppendBridgeRuleMatch(tx, kPostToolUseRule, mode, action,
                        mode == PackageMode::kOn,
                        "post_tool_use hook evaluated");
  if (mode != PackageMode::kOn) {
    return PassthroughResponse();
  }
  return response;
}

}  // namespace sg
