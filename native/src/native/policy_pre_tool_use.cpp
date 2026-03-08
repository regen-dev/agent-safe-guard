#include "sg/policy_pre_tool_use.hpp"

#include "sg/catalog_rule_compiler.hpp"
#include "sg/json_extract.hpp"
#include "sg/rule_audit.hpp"
#include "sg/rule_engine.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
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

constexpr int kDefaultWriteMaxBytes = 102400;
constexpr int kDefaultEditMaxBytes = 51200;
constexpr int kDefaultNotebookMaxBytes = 51200;
constexpr int kDefaultCallLimit = 30;
constexpr int kDefaultByteLimit = 102400;
constexpr std::uintmax_t kLargeFileThreshold = 1024 * 1024;
constexpr std::string_view kCommandPackage = "command-defense";
constexpr std::string_view kReadPackage = "read-defense";
constexpr std::string_view kAgentPackage = "agent-defense";

struct BudgetDecision {
  std::optional<std::string> deny_reason;
  std::optional<std::string> warning;
};

struct RequestConfig {
  int write_max_bytes = kDefaultWriteMaxBytes;
  int edit_max_bytes = kDefaultEditMaxBytes;
  int notebook_max_bytes = kDefaultNotebookMaxBytes;
  int default_call_limit = kDefaultCallLimit;
  int default_byte_limit = kDefaultByteLimit;
  std::filesystem::path subagent_state_dir = "/tmp/.sg-subagent-state";
};

int ReadEnvInt(const char* name, int fallback) {
  const char* raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') {
    return fallback;
  }

  char* end = nullptr;
  const long value = std::strtol(raw, &end, 10);
  if (end == raw || *end != '\0' || value <= 0) {
    return fallback;
  }
  if (value > static_cast<long>(std::numeric_limits<int>::max())) {
    return fallback;
  }
  return static_cast<int>(value);
}

std::string ReadEnv(const char* name, const std::string& fallback = "") {
  const char* raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') {
    return fallback;
  }
  return raw;
}

std::string JsonDeny(std::string_view reason) {
  return "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"" +
         JsonEscape(reason) + "\"}}";
}

std::string JsonSuppress(const std::optional<std::string>& warning = std::nullopt) {
  if (!warning.has_value()) {
    return "{\"suppressOutput\":true}";
  }
  return "{\"suppressOutput\":true,\"warning\":\"" + JsonEscape(*warning) +
         "\"}";
}

std::string Trim(std::string_view input) {
  std::size_t first = 0;
  while (first < input.size() &&
         std::isspace(static_cast<unsigned char>(input[first])) != 0) {
    ++first;
  }
  std::size_t last = input.size();
  while (last > first &&
         std::isspace(static_cast<unsigned char>(input[last - 1])) != 0) {
    --last;
  }
  return std::string(input.substr(first, last - first));
}

std::string NormalizeSpaces(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  bool in_space = false;

  for (const unsigned char ch : input) {
    if (std::isspace(ch) != 0) {
      if (!in_space) {
        out.push_back(' ');
        in_space = true;
      }
    } else {
      out.push_back(static_cast<char>(ch));
      in_space = false;
    }
  }
  return Trim(out);
}

std::string ToLower(std::string_view input) {
  std::string out(input);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

bool ContainsAny(std::string_view haystack,
                 const std::vector<std::string_view>& needles) {
  for (const auto needle : needles) {
    if (haystack.find(needle) != std::string_view::npos) {
      return true;
    }
  }
  return false;
}

bool StartsWith(std::string_view value, std::string_view prefix) {
  return value.size() >= prefix.size() &&
         value.substr(0, prefix.size()) == prefix;
}

bool RegexMatch(const std::string& value, const std::regex& re) {
  return std::regex_search(value.begin(), value.end(), re);
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

bool IsSubagent(const std::string& transcript_path) {
  return transcript_path.find("/subagents/") != std::string::npos ||
         transcript_path.find("/tmp/") != std::string::npos;
}

std::string GetAgentId(const std::string& transcript_path) {
  if (transcript_path.find("/subagents/") == std::string::npos) {
    return "";
  }

  std::filesystem::path p(transcript_path);
  std::string base = p.filename().string();
  if (base.size() > 6 && base.substr(base.size() - 6) == ".jsonl") {
    base.resize(base.size() - 6);
  }
  if (StartsWith(base, "agent-")) {
    base.erase(0, 6);
  }
  return SanitizeId(base);
}

std::string ReadTextFile(const std::filesystem::path& path) {
  std::ifstream in(path);
  if (!in) {
    return "";
  }
  std::ostringstream out;
  out << in.rdbuf();
  return out.str();
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& content) {
  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    return false;
  }
  out << content;
  return static_cast<bool>(out);
}

std::string GetAgentType(const std::filesystem::path& state_dir,
                         const std::string& agent_id) {
  if (agent_id.empty()) {
    return "";
  }
  const std::string content = ReadTextFile(state_dir / agent_id);
  if (content.empty()) {
    return "";
  }
  for (std::string line; std::getline(std::istringstream(content), line);) {
    if (StartsWith(line, "AGENT_TYPE=")) {
      return line.substr(11);
    }
  }
  return "";
}

int ParseIntSafe(const std::string& value, int fallback = 0) {
  const std::string trimmed = Trim(value);
  if (trimmed.empty()) {
    return fallback;
  }
  char* end = nullptr;
  const long parsed = std::strtol(trimmed.c_str(), &end, 10);
  if (end == trimmed.c_str() || *end != '\0') {
    return fallback;
  }
  if (parsed < 0 || parsed > static_cast<long>(std::numeric_limits<int>::max())) {
    return fallback;
  }
  return static_cast<int>(parsed);
}

int ParseMaybeInt(const std::optional<std::string>& value, int fallback) {
  if (!value.has_value()) {
    return fallback;
  }
  return ParseIntSafe(*value, fallback);
}

int ParseCallCount(const std::string& file_content) {
  if (file_content.find('|') == std::string::npos) {
    return ParseIntSafe(file_content, 0);
  }
  std::vector<std::string> parts;
  std::istringstream in(file_content);
  std::string part;
  while (std::getline(in, part, '|')) {
    parts.push_back(part);
  }
  if (parts.size() < 2) {
    return 0;
  }
  return ParseIntSafe(parts[1], 0);
}

int ParseByteCount(const std::string& file_content) {
  if (file_content.find('|') == std::string::npos) {
    return ParseIntSafe(file_content, 0);
  }
  std::vector<std::string> parts;
  std::istringstream in(file_content);
  std::string part;
  while (std::getline(in, part, '|')) {
    parts.push_back(part);
  }
  if (parts.empty()) {
    return 0;
  }
  return ParseIntSafe(parts[0], 0);
}

int CallLimitFor(const std::string& agent_type, int default_call_limit) {
  if (!agent_type.empty()) {
    const std::string env_name = "SG_CALL_LIMIT_" + agent_type;
    return ReadEnvInt(env_name.c_str(), default_call_limit);
  }
  return default_call_limit;
}

int ByteLimitFor(const std::string& agent_type, int default_byte_limit) {
  if (!agent_type.empty()) {
    const std::string env_name = "SG_BYTE_LIMIT_" + agent_type;
    return ReadEnvInt(env_name.c_str(), default_byte_limit);
  }
  return default_byte_limit;
}

long UnixNowInternal() {
  return static_cast<long>(std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now()));
}

BudgetDecision EnforceSubagentBudget(const std::filesystem::path& state_dir,
                                     const std::string& agent_id,
                                     const std::string& agent_type,
                                     int default_call_limit,
                                     int default_byte_limit) {
  BudgetDecision decision;
  if (agent_id.empty()) {
    return decision;
  }

  std::error_code ec;
  std::filesystem::create_directories(state_dir, ec);

  const int call_budget = CallLimitFor(agent_type, default_call_limit);
  const int byte_budget = ByteLimitFor(agent_type, default_byte_limit);
  const int warn_call_at = (call_budget * 80) / 100;
  const int warn_byte_at = (byte_budget * 80) / 100;

  const std::filesystem::path call_file = state_dir / (agent_id + ".calls");
  const std::filesystem::path byte_file = state_dir / (agent_id + ".bytes");

  const int current_calls = ParseCallCount(ReadTextFile(call_file));
  const int new_calls = current_calls + 1;
  (void)WriteTextFile(call_file, agent_id + "|" + std::to_string(new_calls) + "|" +
                                     std::to_string(UnixNowInternal()) + "\n");

  const int current_bytes = ParseByteCount(ReadTextFile(byte_file));

  const std::string at = agent_type.empty() ? "unknown" : agent_type;
  if (new_calls >= call_budget) {
    decision.deny_reason = "Budget exceeded: " + at + " calls " +
                           std::to_string(new_calls) + "/" +
                           std::to_string(call_budget) +
                           ". Stop and report findings.";
    return decision;
  }

  if (new_calls >= warn_call_at) {
    decision.warning = "WARNING: Tool call #" + std::to_string(new_calls) + "/" +
                       std::to_string(call_budget) + " for " + at + " agent.";
  }

  if (current_bytes >= byte_budget) {
    decision.deny_reason = "Budget exceeded: " + at + " output " +
                           std::to_string(current_bytes) + "B/" +
                           std::to_string(byte_budget) +
                           "B. Stop and report findings.";
    return decision;
  }
  if (current_bytes >= warn_byte_at && !decision.warning.has_value()) {
    decision.warning = "WARNING: " + std::to_string(current_bytes) + "B/" +
                       std::to_string(byte_budget / 1024) +
                       "KB cumulative output for " + at + " agent.";
  }

  return decision;
}

bool HasQuietOrPipe(const std::string& lower_command) {
  return ContainsAny(lower_command,
                     {" -q", "--silent", "--quiet", "|", ">", "&"});
}

bool HasAnyPipeExec(const std::string& lower, const std::string_view downloader) {
  if (lower.find(downloader) == std::string::npos) {
    return false;
  }
  return ContainsAny(lower, {"| bash", "| sh", "| zsh", "| python", "| python3",
                             "| perl", "| ruby", "| node"});
}

bool IsHomeRootPath(const std::string& path) {
  if (path == "~" || path == "/root") {
    return true;
  }
  if (path.rfind("/home/", 0) != 0) {
    return false;
  }
  const std::string user_segment = path.substr(6);
  return !user_segment.empty() && user_segment.find('/') == std::string::npos;
}

std::vector<std::string> SplitArgs(const std::string& command) {
  std::vector<std::string> out;
  std::istringstream in(command);
  std::string tok;
  while (in >> tok) {
    if (tok.size() >= 2 && ((tok.front() == '"' && tok.back() == '"') ||
                            (tok.front() == '\'' && tok.back() == '\''))) {
      tok = tok.substr(1, tok.size() - 2);
    }
    out.push_back(tok);
  }
  return out;
}

bool IsLikelyBinaryFile(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  char buf[4096];
  in.read(buf, sizeof(buf));
  const std::streamsize n = in.gcount();
  for (std::streamsize i = 0; i < n; ++i) {
    if (buf[i] == '\0') {
      return true;
    }
  }
  return false;
}

RequestConfig LoadRequestConfig(std::string_view request_json) {
  RequestConfig cfg;

  cfg.write_max_bytes = ReadEnvInt("SG_WRITE_MAX_BYTES", kDefaultWriteMaxBytes);
  cfg.edit_max_bytes = ReadEnvInt("SG_EDIT_MAX_BYTES", kDefaultEditMaxBytes);
  cfg.notebook_max_bytes =
      ReadEnvInt("SG_NOTEBOOK_MAX_BYTES", kDefaultNotebookMaxBytes);
  cfg.default_call_limit = ReadEnvInt("SG_DEFAULT_CALL_LIMIT", kDefaultCallLimit);
  cfg.default_byte_limit = ReadEnvInt("SG_DEFAULT_BYTE_LIMIT", kDefaultByteLimit);

  cfg.write_max_bytes =
      ParseMaybeInt(FindJsonString(request_json, "sg_write_max_bytes"),
                    cfg.write_max_bytes);
  cfg.edit_max_bytes =
      ParseMaybeInt(FindJsonString(request_json, "sg_edit_max_bytes"),
                    cfg.edit_max_bytes);
  cfg.notebook_max_bytes =
      ParseMaybeInt(FindJsonString(request_json, "sg_notebook_max_bytes"),
                    cfg.notebook_max_bytes);
  cfg.default_call_limit =
      ParseMaybeInt(FindJsonString(request_json, "sg_default_call_limit"),
                    cfg.default_call_limit);
  cfg.default_byte_limit =
      ParseMaybeInt(FindJsonString(request_json, "sg_default_byte_limit"),
                    cfg.default_byte_limit);

  const auto req_state_dir =
      FindJsonString(request_json, "sg_subagent_state_dir");
  if (req_state_dir.has_value() && !req_state_dir->empty()) {
    cfg.subagent_state_dir = *req_state_dir;
  } else {
    cfg.subagent_state_dir =
        ReadEnv("SG_SUBAGENT_STATE_DIR", "/tmp/.sg-subagent-state");
  }

  return cfg;
}

std::string_view FieldOrEmpty(const Transaction& tx, std::string_view key) {
  const auto value = GetTransactionField(tx, key);
  if (!value.has_value()) {
    return {};
  }
  return *value;
}

bool FieldIsTrue(const Transaction& tx, std::string_view key) {
  return FieldOrEmpty(tx, key) == "1";
}

int FieldInt(const Transaction& tx, std::string_view key, int fallback = 0) {
  const auto value = GetTransactionField(tx, key);
  if (!value.has_value()) {
    return fallback;
  }
  return ParseIntSafe(std::string(*value), fallback);
}

bool IsBuildArtifact(std::string_view lower_command) {
  static const std::regex kBuildArtifact(
      R"((\.vite/build|/dist/[^/]+\.(js|css)|\.min\.(js|css)|bundle\.(js|css)))");
  return RegexMatch(std::string(lower_command), kBuildArtifact);
}

std::string JsonSuppressFor(const Transaction& tx) {
  const auto warning = GetTransactionField(tx, "warning");
  if (warning.has_value() && !warning->empty()) {
    return JsonSuppress(std::string(*warning));
  }
  return JsonSuppress();
}

CompiledRule MakeRule(int rule_id, std::string_view package, std::string name,
                      RuleSeverity severity, RuleMatcher matcher) {
  CompiledRule rule;
  rule.meta.rule_id = rule_id;
  rule.meta.package = std::string(package);
  rule.meta.name = std::move(name);
  rule.meta.phase = RulePhase::kPreToolUse;
  rule.meta.severity = severity;
  rule.match = std::move(matcher);
  return rule;
}

Transaction BuildTransaction(std::string_view request_json, const RequestConfig& cfg,
                             bool is_subagent, std::string_view agent_id,
                             std::string_view agent_type,
                             const BudgetDecision& budget) {
  Transaction tx;
  tx.phase = RulePhase::kPreToolUse;
  tx.raw_request_json = std::string(request_json);
  tx.session_id = FindJsonString(request_json, "session_id").value_or("");
  tx.tool_name = FindJsonString(request_json, "tool_name").value_or("");
  tx.transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");

  const std::string content = FindJsonString(request_json, "content").value_or("");
  const std::string new_string =
      FindJsonString(request_json, "new_string").value_or("");
  const std::string new_source =
      FindJsonString(request_json, "new_source").value_or("");
  const std::string pattern = FindJsonString(request_json, "pattern").value_or("");
  const std::string path = FindJsonString(request_json, "path").value_or("");
  const std::string command = FindJsonString(request_json, "command").value_or("");
  const std::string normalized = NormalizeSpaces(command);
  const std::string lower = ToLower(normalized);

  SetTransactionField(&tx, "is_subagent", is_subagent ? "1" : "0");
  SetTransactionField(&tx, "agent_id", std::string(agent_id));
  SetTransactionField(&tx, "agent_type", std::string(agent_type));
  if (budget.warning.has_value()) {
    SetTransactionField(&tx, "warning", *budget.warning);
  }
  if (budget.deny_reason.has_value()) {
    SetTransactionField(&tx, "budget_deny_reason", *budget.deny_reason);
  }

  SetTransactionField(&tx, "content_size", std::to_string(content.size()));
  SetTransactionField(&tx, "write_max_bytes", std::to_string(cfg.write_max_bytes));
  SetTransactionField(&tx, "new_string_size", std::to_string(new_string.size()));
  SetTransactionField(&tx, "edit_max_bytes", std::to_string(cfg.edit_max_bytes));
  SetTransactionField(&tx, "new_source_size", std::to_string(new_source.size()));
  SetTransactionField(&tx, "notebook_max_bytes",
                      std::to_string(cfg.notebook_max_bytes));
  SetTransactionField(&tx, "glob_pattern", pattern);
  SetTransactionField(&tx, "glob_path", path);
  SetTransactionField(&tx, "command", command);
  SetTransactionField(&tx, "normalized_command", normalized);
  SetTransactionField(&tx, "lower_command", lower);

  return tx;
}

std::vector<CompiledRule> BuildRules() {
  std::vector<CompiledRule> rules;
  rules.reserve(30);

  rules.push_back(MakeRule(
      150100, kAgentPackage, "subagent_budget_limit", RuleSeverity::kHigh,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        const std::string_view reason = FieldOrEmpty(tx, "budget_deny_reason");
        if (reason.empty()) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = std::string(reason);
        outcome.matched_field = "subagent.budget";
        outcome.matched_value = std::string(reason);
        outcome.response_payload = JsonDeny(reason);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100100, kCommandPackage, "write_max_bytes", RuleSeverity::kHigh,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Write") {
          return std::nullopt;
        }
        if (FieldInt(tx, "content_size") <= FieldInt(tx, "write_max_bytes")) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Write exceeds configured byte limit";
        outcome.matched_field = "tool_input.content";
        outcome.matched_value = std::to_string(FieldInt(tx, "content_size"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100110, kCommandPackage, "edit_max_bytes", RuleSeverity::kHigh,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Edit") {
          return std::nullopt;
        }
        if (FieldInt(tx, "new_string_size") <= FieldInt(tx, "edit_max_bytes")) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Edit exceeds configured byte limit";
        outcome.matched_field = "tool_input.new_string";
        outcome.matched_value = std::to_string(FieldInt(tx, "new_string_size"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100120, kCommandPackage, "notebook_max_bytes", RuleSeverity::kHigh,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "NotebookEdit") {
          return std::nullopt;
        }
        if (FieldInt(tx, "new_source_size") <= FieldInt(tx, "notebook_max_bytes")) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "NotebookEdit exceeds configured byte limit";
        outcome.matched_field = "tool_input.new_source";
        outcome.matched_value = std::to_string(FieldInt(tx, "new_source_size"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100130, kCommandPackage, "glob_home_recursive", RuleSeverity::kHigh,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Glob") {
          return std::nullopt;
        }
        const std::string pattern(FieldOrEmpty(tx, "glob_pattern"));
        if (pattern.find("**") == std::string::npos) {
          return std::nullopt;
        }

        const std::string path(FieldOrEmpty(tx, "glob_path"));
        if (!path.empty() && !IsHomeRootPath(path) && !StartsWith(pattern, "/home/") &&
            !StartsWith(pattern, "~/")) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Glob ** in home dir; narrow path or use fd";
        outcome.matched_field = "tool_input.pattern";
        outcome.matched_value = pattern;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100200, kCommandPackage, "destructive_command", RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string_view lower = FieldOrEmpty(tx, "lower_command");
        if (lower.empty() ||
            !ContainsAny(lower,
                         {"rm -rf /", "rm -fr /", "rm -rf ~", "rm -fr ~",
                          "rm -rf .", "rm -fr .", "rm --recursive --force",
                          "rm --force --recursive", "rm -rf --no-preserve-root",
                          "mkfs", "dd if=", "dd of=/dev/", "> /dev/sd",
                          "> /dev/nvme", "chmod -r 777 /", "chown -r ",
                          "chown --recursive"})) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked destructive command";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100210, kCommandPackage, "fork_bomb", RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string normalized(FieldOrEmpty(tx, "normalized_command"));
        if (normalized.empty()) {
          return std::nullopt;
        }
        static const std::regex kForkBomb(
            R"(:\(\)[[:space:]]*\{[[:space:]]*:\|:[[:space:]]*&[[:space:]]*\})");
        if (!RegexMatch(normalized, kForkBomb)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked fork bomb";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = normalized;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100220, kCommandPackage, "remote_code_execution",
      RuleSeverity::kCritical,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (lower.empty()) {
          return std::nullopt;
        }

        const bool has_pipe_rce =
            HasAnyPipeExec(lower, "curl") || HasAnyPipeExec(lower, "wget");
        const bool has_process_substitution =
            ContainsAny(lower, {"bash <(curl", "sh <(curl", "zsh <(curl",
                                "python <(curl", "python3 <(curl", "bash <(wget",
                                "sh <(wget", "zsh <(wget", "python <(wget",
                                "python3 <(wget"});
        const bool has_chain_exec =
            ((lower.find("curl") != std::string::npos ||
              lower.find("wget") != std::string::npos) &&
             ContainsAny(lower, {"&& bash", "&& sh", "; bash", "; sh"}));
        if (!has_pipe_rce && !has_process_substitution && !has_chain_exec) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Blocked remote code execution";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      150200, kAgentPackage, "subagent_prefer_glob_over_find",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || !FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        static const std::regex kSubFind(
            R"((^|[[:space:];&|])[[:space:]]*find[[:space:]])");
        const std::string normalized(FieldOrEmpty(tx, "normalized_command"));
        if (!RegexMatch(normalized, kSubFind)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use Glob tool instead of find";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = normalized;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      150210, kAgentPackage, "subagent_prefer_grep_tool_over_xargs_grep",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || !FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        static const std::regex kSubXargsGrep(R"(xargs[[:space:]]+(grep|rg))");
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!RegexMatch(lower, kSubXargsGrep)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use Grep tool instead of xargs grep";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      150220, kAgentPackage, "subagent_prefer_grep_tool_over_grep",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || !FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        static const std::regex kSubGrep(
            R"((^|[;&]|&&|\|\|)[[:space:]]*grep[[:space:]])");
        const std::string normalized(FieldOrEmpty(tx, "normalized_command"));
        if (!RegexMatch(normalized, kSubGrep)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use Grep tool or rg instead of grep";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = normalized;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      150230, kAgentPackage, "subagent_prefer_tree_or_glob_over_ls_la",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || !FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        static const std::regex kSubLs(
            R"(^[[:space:]]*ls[[:space:]].*(-la|-al|-lah|-lha))");
        const std::string normalized(FieldOrEmpty(tx, "normalized_command"));
        if (!RegexMatch(normalized, kSubLs)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use tree -L 2 or Glob tool instead of ls -la";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = normalized;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      150240, kAgentPackage, "subagent_no_cat_glob", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || !FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        static const std::regex kSubCatGlob(R"(^[[:space:]]*cat[[:space:]].*\*)");
        const std::string normalized(FieldOrEmpty(tx, "normalized_command"));
        if (!RegexMatch(normalized, kSubCatGlob)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use Glob then Read for pattern-matched files";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = normalized;
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      150250, kAgentPackage, "subagent_no_cat_many_files",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || !FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!StartsWith(lower, "cat ") || lower.find('|') != std::string::npos) {
          return std::nullopt;
        }

        int file_args = 0;
        for (const auto& tok : SplitArgs(std::string(FieldOrEmpty(tx, "normalized_command")))) {
          if (tok == "cat") {
            continue;
          }
          if (!tok.empty() && tok[0] != '-') {
            ++file_args;
          }
        }
        if (file_args <= 2) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use Read tool for multiple files (parallel)";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100300, kCommandPackage, "ffmpeg_requires_quiet_flags",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (lower.find("ffmpeg") == std::string::npos) {
          return std::nullopt;
        }
        if (lower.find("-nostats") != std::string::npos &&
            lower.find("-loglevel error") != std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "ffmpeg commands must include -nostats -loglevel error";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100310, kReadPackage, "force_read_override", RuleSeverity::kInfo,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (lower.find("# force_read") == std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kSuppress;
        outcome.terminal = true;
        outcome.message = "Force-read override honored";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonSuppressFor(tx);
        return outcome;
      }));

  rules.push_back(MakeRule(
      300120, kReadPackage, "inspect_file_metadata", RuleSeverity::kInfo,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        static const std::regex kMetadata(
            R"(^[[:space:]]*(wc|stat|file|du|md5sum|sha256sum|sha1sum|cksum)[[:space:]])");
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!RegexMatch(lower, kMetadata)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kSuppress;
        outcome.terminal = true;
        outcome.message = "Metadata inspection allowed";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonSuppressFor(tx);
        return outcome;
      }));

  rules.push_back(MakeRule(
      300130, kReadPackage, "limited_pipe_inspection", RuleSeverity::kInfo,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (IsBuildArtifact(lower)) {
          return std::nullopt;
        }
        static const std::regex kLimitedPipe(
            R"(\|[[:space:]]*(head|tail|wc|grep|awk|sed)[[:space:]])");
        if (!RegexMatch(lower, kLimitedPipe)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kSuppress;
        outcome.terminal = true;
        outcome.message = "Limited pipe inspection allowed";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonSuppressFor(tx);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100400, kCommandPackage, "git_commit_requires_quiet",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (lower.find("git commit") == std::string::npos ||
            lower.find("-q") != std::string::npos ||
            lower.find("--quiet") != std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Use git commit -q";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100410, kCommandPackage, "git_log_requires_limit", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!StartsWith(lower, "git log")) {
          return std::nullopt;
        }
        if (ContainsAny(lower,
                        {" -n", " --oneline", " --format", " --pretty",
                         " --since", " --after", "| head", "| tail"})) {
          return std::nullopt;
        }
        static const std::regex kNumericShort(R"((^|[[:space:]])-[0-9]+([[:space:]]|$))");
        if (RegexMatch(lower, kNumericShort)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "git log needs -n, --oneline, or pipe";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100420, kCommandPackage, "npm_requires_silent", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!(StartsWith(lower, "npm install") || StartsWith(lower, "npm i ") ||
              StartsWith(lower, "npm ci")) ||
            HasQuietOrPipe(lower)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "npm install/ci needs --silent or pipe";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100430, kCommandPackage, "cargo_build_requires_quiet",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!StartsWith(lower, "cargo build") || HasQuietOrPipe(lower)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "cargo build needs -q or pipe";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100440, kCommandPackage, "make_requires_silent", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!StartsWith(lower, "make") || HasQuietOrPipe(lower) ||
            lower == "make -s" || lower.find("--silent") != std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "make needs -s or pipe";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100450, kCommandPackage, "pip_requires_quiet", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!(StartsWith(lower, "pip install") || StartsWith(lower, "pip download")) ||
            lower.find("-q") != std::string::npos ||
            lower.find("--quiet") != std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "pip needs -q";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100460, kCommandPackage, "curl_verbose_requires_output",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!StartsWith(lower, "curl ") ||
            (lower.find(" -v") == std::string::npos &&
             lower.find(" --verbose") == std::string::npos) ||
            ContainsAny(lower, {"|", ">", " -o ", " -o", " -o/", " -o\t",
                                " -O", " --output", " --remote-name"})) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "curl -v needs output redirection";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100470, kCommandPackage, "wget_requires_quiet", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        static const std::regex kWgetOutputFlag(
            R"((^|[[:space:]])-o([[:space:]]|$))");
        if (!StartsWith(lower, "wget ") || lower.find("-q") != std::string::npos ||
            lower.find("--quiet") != std::string::npos ||
            RegexMatch(lower, kWgetOutputFlag)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "wget needs -q";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100480, kCommandPackage, "docker_requires_quiet", RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!(StartsWith(lower, "docker build") || StartsWith(lower, "docker pull")) ||
            lower.find("-q") != std::string::npos ||
            lower.find("--quiet") != std::string::npos ||
            lower.find('|') != std::string::npos) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "docker build/pull needs -q or pipe";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      300200, kReadPackage, "minified_grep_requires_limit",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!IsBuildArtifact(lower)) {
          return std::nullopt;
        }

        static const std::regex kGrep(R"((^|[[:space:]])grep[[:space:]])");
        if (!RegexMatch(lower, kGrep)) {
          return std::nullopt;
        }

        const bool has_grep_allow =
            RegexMatch(lower, std::regex(
                                   R"(head[[:space:]]+-c[[:space:]]*[0-9]+.*\|[[:space:]]*grep)")) ||
            RegexMatch(lower, std::regex(R"((^|[[:space:]])-l([[:space:]]|$))")) ||
            lower.find("--files-with-matches") != std::string::npos ||
            RegexMatch(lower, std::regex(R"(\|[[:space:]]*(wc|head|tail))"));
        if (has_grep_allow) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "grep on minified file; use Grep tool or pipe head -c first";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      300210, kReadPackage, "minified_cat_requires_byte_bound",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!IsBuildArtifact(lower)) {
          return std::nullopt;
        }

        const bool is_cat_head_tail =
            RegexMatch(lower, std::regex(
                                   R"((^|[[:space:]])(cat|head|tail)[[:space:]])"));
        const bool has_c_bound =
            RegexMatch(lower, std::regex(R"((-c[[:space:]]*[0-9]+))"));
        if (!is_cat_head_tail || has_c_bound) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "Minified file; use head -c 4000";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100500, kReadPackage, "grep_recursive_requires_rg_or_limit",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash" || FieldIsTrue(tx, "is_subagent")) {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        const bool has_grep =
            RegexMatch(lower, std::regex(R"((^|[[:space:]])grep[[:space:]])"));
        const bool has_recursive = RegexMatch(
            lower, std::regex(R"(grep.*([[:space:]]-[a-zA-Z]*[rR][a-zA-Z]*|--recursive))"));
        const bool has_l = RegexMatch(
            lower, std::regex(R"((^|[[:space:]])(-l|--files-with-matches)([[:space:]]|$))"));
        const bool has_pipe_limiter =
            RegexMatch(lower, std::regex(R"(\|[[:space:]]*(head|tail|wc))"));
        if (!has_grep || !has_recursive || has_l || has_pipe_limiter) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = RuleAction::kDeny;
        outcome.terminal = true;
        outcome.message = "grep -r scans all - use rg or grep -l";
        outcome.matched_field = "tool_input.command";
        outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
        outcome.response_payload = JsonDeny(outcome.message);
        return outcome;
      }));

  rules.push_back(MakeRule(
      100510, kReadPackage, "find_sensitive_trees_requires_limit",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        static const std::regex kFind(R"((^|[[:space:]])find[[:space:]])");
        if (!RegexMatch(lower, kFind)) {
          return std::nullopt;
        }

        static const std::regex kMaxDepth(R"((-maxdepth[[:space:]]+[1-3]))");
        static const std::regex kPipeLimiter(R"(\|[[:space:]]*(head|tail|wc))");
        static const std::regex kName(R"((-name[[:space:]]+))");
        if (RegexMatch(lower, kMaxDepth) || RegexMatch(lower, kPipeLimiter) ||
            RegexMatch(lower, kName)) {
          return std::nullopt;
        }

        for (const auto* pat : {".claude", ".git", "node_modules"}) {
          if (lower.find(pat) == std::string::npos) {
            continue;
          }

          RuleOutcome outcome;
          outcome.action = RuleAction::kDeny;
          outcome.terminal = true;
          outcome.message = std::string("find in ") + pat + " needs -maxdepth or pipe";
          outcome.matched_field = "tool_input.command";
          outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
          outcome.response_payload = JsonDeny(outcome.message);
          return outcome;
        }
        return std::nullopt;
      }));

  rules.push_back(MakeRule(
      300220, kReadPackage, "head_tail_small_window", RuleSeverity::kInfo,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        static const std::regex kHeadTail(R"(^[[:space:]]*(head|tail))");
        if (!RegexMatch(lower, kHeadTail)) {
          return std::nullopt;
        }

        std::smatch match;
        if (std::regex_search(lower, match, std::regex(R"(-n[[:space:]]*([0-9]+))")) &&
            match.size() > 1 && ParseIntSafe(match[1].str(), 10000) <= 500) {
          RuleOutcome outcome;
          outcome.action = RuleAction::kSuppress;
          outcome.terminal = true;
          outcome.message = "Small head/tail window allowed";
          outcome.matched_field = "tool_input.command";
          outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
          outcome.response_payload = JsonSuppressFor(tx);
          return outcome;
        }
        if (std::regex_search(
                lower, match,
                std::regex(R"((^|[[:space:]])-([0-9]+)([[:space:]]|$))")) &&
            match.size() > 2 && ParseIntSafe(match[2].str(), 10000) <= 500) {
          RuleOutcome outcome;
          outcome.action = RuleAction::kSuppress;
          outcome.terminal = true;
          outcome.message = "Small head/tail window allowed";
          outcome.matched_field = "tool_input.command";
          outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
          outcome.response_payload = JsonSuppressFor(tx);
          return outcome;
        }
        if (std::regex_search(lower, match, std::regex(R"(--lines=([0-9]+))")) &&
            match.size() > 1 && ParseIntSafe(match[1].str(), 10000) <= 500) {
          RuleOutcome outcome;
          outcome.action = RuleAction::kSuppress;
          outcome.terminal = true;
          outcome.message = "Small head/tail window allowed";
          outcome.matched_field = "tool_input.command";
          outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
          outcome.response_payload = JsonSuppressFor(tx);
          return outcome;
        }
        return std::nullopt;
      }));

  rules.push_back(MakeRule(
      300300, kReadPackage, "cat_large_or_binary_file",
      RuleSeverity::kMedium,
      [](const Transaction& tx) -> std::optional<RuleOutcome> {
        if (tx.tool_name != "Bash") {
          return std::nullopt;
        }
        const std::string lower(FieldOrEmpty(tx, "lower_command"));
        if (!StartsWith(lower, "cat ")) {
          return std::nullopt;
        }

        std::vector<std::string> args = SplitArgs(std::string(FieldOrEmpty(tx, "normalized_command")));
        std::vector<std::string> paths;
        for (const auto& tok : args) {
          if (tok == "cat") {
            continue;
          }
          if (!tok.empty() && tok[0] != '-') {
            paths.push_back(tok);
          }
        }
        if (paths.size() != 1) {
          return std::nullopt;
        }

        std::error_code ec;
        const std::filesystem::path path(paths[0]);
        if (!std::filesystem::is_regular_file(path, ec)) {
          return std::nullopt;
        }
        const auto size = std::filesystem::file_size(path, ec);
        if (!ec && size > kLargeFileThreshold) {
          RuleOutcome outcome;
          outcome.action = RuleAction::kDeny;
          outcome.terminal = true;
          outcome.message = "File >1MB; use head/tail or Read offset/limit";
          outcome.matched_field = "tool_input.command";
          outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
          outcome.response_payload = JsonDeny(outcome.message);
          return outcome;
        }
        if (!ec && IsLikelyBinaryFile(path)) {
          RuleOutcome outcome;
          outcome.action = RuleAction::kDeny;
          outcome.terminal = true;
          outcome.message = "Blocked binary file read; use file/hexdump";
          outcome.matched_field = "tool_input.command";
          outcome.matched_value = std::string(FieldOrEmpty(tx, "command"));
          outcome.response_payload = JsonDeny(outcome.message);
          return outcome;
        }
        return std::nullopt;
      }));

  return rules;
}

void AppendAudit(const Transaction& tx, const EngineResult& result) {
  for (const auto& match : result.matches) {
    AppendRuleMatchEvent(tx, match);
  }
  for (const auto& error : result.errors) {
    AppendRuleErrorEvent(tx, error);
  }
}

}  // namespace

std::string EvaluatePreToolUse(std::string_view request_json) {
  const RequestConfig cfg = LoadRequestConfig(request_json);
  const auto transcript_path =
      FindJsonString(request_json, "transcript_path").value_or("");
  const bool is_subagent = IsSubagent(transcript_path);
  const std::string agent_id = GetAgentId(transcript_path);
  const std::string agent_type = GetAgentType(cfg.subagent_state_dir, agent_id);

  BudgetDecision budget;
  if (is_subagent && !agent_id.empty()) {
    budget = EnforceSubagentBudget(cfg.subagent_state_dir, agent_id, agent_type,
                                   cfg.default_call_limit, cfg.default_byte_limit);
  }

  const Transaction tx =
      BuildTransaction(request_json, cfg, is_subagent, agent_id, agent_type, budget);
  std::vector<CompiledRule> rules = BuildRules();
  // Append catalog/marketplace rules after built-in rules.
  const auto catalog_rules = GetCatalogCompiledRules(RulePhase::kPreToolUse);
  rules.insert(rules.end(), catalog_rules.begin(), catalog_rules.end());
  const EngineResult result = EvaluateRules(tx, rules);
  AppendAudit(tx, result);

  if (result.enforced.has_value()) {
    return result.enforced->response_payload;
  }
  return JsonSuppressFor(tx);
}

std::vector<RuleMetadata> ListPreToolUseRules() {
  std::vector<RuleMetadata> metadata;
  for (const auto& rule : BuildRules()) {
    metadata.push_back(rule.meta);
  }
  // Include catalog/marketplace rules.
  const auto catalog = ListCatalogRulesForPhase(RulePhase::kPreToolUse);
  metadata.insert(metadata.end(), catalog.begin(), catalog.end());
  return metadata;
}

}  // namespace sg
