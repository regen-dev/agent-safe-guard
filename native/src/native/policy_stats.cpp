#include "sg/policy_stats.hpp"

#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_state.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

namespace sg {
namespace {

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

std::filesystem::path StatsDir() { return DefaultPolicyDir() / "stats"; }

std::filesystem::path RulesStatsPath() { return StatsDir() / "rules.json"; }

std::filesystem::path PackagesStatsPath() { return StatsDir() / "packages.json"; }

std::filesystem::path InstalledStatePath() {
  return DefaultPolicyDir() / "installed.json";
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

bool AtomicWrite(const std::filesystem::path& path, const std::string& content) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    return false;
  }

  const auto tmp =
      path.string() + ".tmp." + std::to_string(static_cast<long long>(::getpid()));
  {
    std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
    if (!out) {
      return false;
    }
    out << content;
    if (!out) {
      return false;
    }
  }

  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    return false;
  }
  return true;
}

void EnsureFile(const std::filesystem::path& path, std::string_view content) {
  std::error_code ec;
  if (std::filesystem::exists(path, ec) && !ec) {
    return;
  }
  (void)AtomicWrite(path, std::string(content));
}

void EnsurePolicyScaffold() {
  EnsurePolicyStateScaffold();
  std::error_code ec;
  std::filesystem::create_directories(StatsDir(), ec);
  std::filesystem::create_directories(DefaultPolicyDir() / "overrides", ec);
  EnsureFile(InstalledStatePath(), "{\"version\":1,\"installed\":[]}\n");
  EnsureFile(RulesStatsPath(),
             "{\"version\":1,\"generated_at\":0,\"rules\":[]}\n");
  EnsureFile(PackagesStatsPath(),
             "{\"version\":1,\"generated_at\":0,\"packages\":[]}\n");
}

std::optional<long> ParseLong(std::string_view raw) {
  const std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  char* end = nullptr;
  const long value = std::strtol(trimmed.c_str(), &end, 10);
  if (end == trimmed.c_str() || *end != '\0') {
    return std::nullopt;
  }
  return value;
}

long RawLongOr(std::string_view json, std::string_view key, long fallback) {
  const auto raw = FindJsonRaw(json, key);
  if (!raw.has_value()) {
    return fallback;
  }
  return ParseLong(*raw).value_or(fallback);
}

std::vector<std::string> SplitJsonObjectArray(std::string_view json) {
  std::vector<std::string> out;
  if (json.size() < 2 || json.front() != '[' || json.back() != ']') {
    return out;
  }

  bool in_string = false;
  bool escaped = false;
  int depth = 0;
  std::size_t start = std::string_view::npos;
  for (std::size_t i = 1; i + 1 < json.size(); ++i) {
    const char ch = json[i];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (ch == '\\') {
        escaped = true;
      } else if (ch == '"') {
        in_string = false;
      }
      continue;
    }

    if (ch == '"') {
      in_string = true;
      continue;
    }
    if (ch == '{') {
      if (depth == 0) {
        start = i;
      }
      ++depth;
      continue;
    }
    if (ch == '}') {
      --depth;
      if (depth == 0 && start != std::string_view::npos) {
        out.emplace_back(json.substr(start, i - start + 1));
        start = std::string_view::npos;
      }
    }
  }
  return out;
}

std::string ProjectRootFromTranscriptPath(std::string_view transcript_path) {
  if (transcript_path.empty()) {
    return "";
  }

  const std::filesystem::path transcript{std::string(transcript_path)};
  if (transcript_path.find("/subagents/") != std::string_view::npos) {
    return transcript.parent_path().parent_path().string();
  }
  return transcript.parent_path().string();
}

std::string RuleDisposition(const EvaluatedRule& rule) {
  if (rule.mode == PackageMode::kDetectionOnly) {
    return "detect_only";
  }
  if (!rule.enforced) {
    return "observed";
  }

  switch (rule.action) {
    case RuleAction::kAllow:
      return "allowed";
    case RuleAction::kSuppress:
      return "suppressed";
    case RuleAction::kModifyOutput:
      return "modified";
    case RuleAction::kDeny:
    case RuleAction::kFailClosed:
      return "blocked";
    case RuleAction::kAppendContext:
    case RuleAction::kLogOnly:
    case RuleAction::kNone:
    default:
      return "observed";
  }
}

void BumpDispositionCounter(RuleStatsSnapshot* entry,
                            const std::string& disposition) {
  if (entry == nullptr) {
    return;
  }
  if (disposition == "blocked") {
    ++entry->blocked_total;
  } else if (disposition == "allowed") {
    ++entry->allowed_total;
  } else if (disposition == "suppressed") {
    ++entry->suppressed_total;
  } else if (disposition == "modified") {
    ++entry->modified_total;
  } else if (disposition == "detect_only") {
    ++entry->detect_only_total;
  }
}

void BumpDispositionCounter(PackageStatsSnapshot* entry,
                            const std::string& disposition) {
  if (entry == nullptr) {
    return;
  }
  if (disposition == "blocked") {
    ++entry->blocked_total;
  } else if (disposition == "allowed") {
    ++entry->allowed_total;
  } else if (disposition == "suppressed") {
    ++entry->suppressed_total;
  } else if (disposition == "modified") {
    ++entry->modified_total;
  } else if (disposition == "detect_only") {
    ++entry->detect_only_total;
  }
}

std::vector<RuleStatsSnapshot> ParseRuleStatsSnapshot() {
  std::vector<RuleStatsSnapshot> entries;
  const std::string raw = ReadFile(RulesStatsPath());
  const auto array = FindJsonRaw(raw, "rules");
  if (!array.has_value()) {
    return entries;
  }

  for (const auto& obj : SplitJsonObjectArray(*array)) {
    RuleStatsSnapshot entry;
    entry.rule_id = static_cast<int>(RawLongOr(obj, "rule_id", 0));
    entry.package = FindJsonString(obj, "package").value_or("");
    entry.rule_name = FindJsonString(obj, "rule_name").value_or("");
    entry.phase = FindJsonString(obj, "phase").value_or("");
    entry.severity = FindJsonString(obj, "severity").value_or("");
    entry.matched_total = RawLongOr(obj, "matched_total", 0);
    entry.blocked_total = RawLongOr(obj, "blocked_total", 0);
    entry.allowed_total = RawLongOr(obj, "allowed_total", 0);
    entry.suppressed_total = RawLongOr(obj, "suppressed_total", 0);
    entry.modified_total = RawLongOr(obj, "modified_total", 0);
    entry.detect_only_total = RawLongOr(obj, "detect_only_total", 0);
    entry.error_total = RawLongOr(obj, "error_total", 0);
    entry.last_matched_at = RawLongOr(obj, "last_matched_at", 0);
    entry.last_blocked_at = RawLongOr(obj, "last_blocked_at", 0);
    entry.last_error_at = RawLongOr(obj, "last_error_at", 0);
    entry.last_disposition = FindJsonString(obj, "last_disposition").value_or("");
    entry.last_project = FindJsonString(obj, "last_project").value_or("");
    entry.last_session_id = FindJsonString(obj, "last_session_id").value_or("");
    if (entry.rule_id != 0) {
      entries.push_back(std::move(entry));
    }
  }
  return entries;
}

std::vector<PackageStatsSnapshot> ParsePackageStatsSnapshot() {
  std::vector<PackageStatsSnapshot> entries;
  const std::string raw = ReadFile(PackagesStatsPath());
  const auto array = FindJsonRaw(raw, "packages");
  if (!array.has_value()) {
    return entries;
  }

  for (const auto& obj : SplitJsonObjectArray(*array)) {
    PackageStatsSnapshot entry;
    entry.package = FindJsonString(obj, "package").value_or("");
    entry.matched_total = RawLongOr(obj, "matched_total", 0);
    entry.blocked_total = RawLongOr(obj, "blocked_total", 0);
    entry.allowed_total = RawLongOr(obj, "allowed_total", 0);
    entry.suppressed_total = RawLongOr(obj, "suppressed_total", 0);
    entry.modified_total = RawLongOr(obj, "modified_total", 0);
    entry.detect_only_total = RawLongOr(obj, "detect_only_total", 0);
    entry.error_total = RawLongOr(obj, "error_total", 0);
    entry.last_matched_at = RawLongOr(obj, "last_matched_at", 0);
    entry.last_blocked_at = RawLongOr(obj, "last_blocked_at", 0);
    entry.last_error_at = RawLongOr(obj, "last_error_at", 0);
    entry.last_disposition = FindJsonString(obj, "last_disposition").value_or("");
    entry.last_project = FindJsonString(obj, "last_project").value_or("");
    entry.last_session_id = FindJsonString(obj, "last_session_id").value_or("");
    if (!entry.package.empty()) {
      entries.push_back(std::move(entry));
    }
  }
  return entries;
}

void WriteRuleStats(const std::vector<RuleStatsSnapshot>& entries) {
  std::vector<RuleStatsSnapshot> sorted = entries;
  std::sort(sorted.begin(), sorted.end(),
            [](const RuleStatsSnapshot& lhs, const RuleStatsSnapshot& rhs) {
              return lhs.rule_id < rhs.rule_id;
            });

  std::ostringstream out;
  out << "{\"version\":1,\"generated_at\":" << UnixNow() << ",\"rules\":[";
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    const auto& entry = sorted[i];
    if (i > 0) {
      out << ',';
    }
    out << "{\"rule_id\":" << entry.rule_id << ",\"package\":\""
        << JsonEscape(entry.package) << "\",\"rule_name\":\""
        << JsonEscape(entry.rule_name) << "\",\"phase\":\""
        << JsonEscape(entry.phase) << "\",\"severity\":\""
        << JsonEscape(entry.severity) << "\",\"matched_total\":"
        << entry.matched_total << ",\"blocked_total\":" << entry.blocked_total
        << ",\"allowed_total\":" << entry.allowed_total
        << ",\"suppressed_total\":" << entry.suppressed_total
        << ",\"modified_total\":" << entry.modified_total
        << ",\"detect_only_total\":" << entry.detect_only_total
        << ",\"error_total\":" << entry.error_total
        << ",\"last_matched_at\":" << entry.last_matched_at
        << ",\"last_blocked_at\":" << entry.last_blocked_at
        << ",\"last_error_at\":" << entry.last_error_at
        << ",\"last_disposition\":\"" << JsonEscape(entry.last_disposition)
        << "\",\"last_project\":\"" << JsonEscape(entry.last_project)
        << "\",\"last_session_id\":\"" << JsonEscape(entry.last_session_id)
        << "\"}";
  }
  out << "]}\n";
  (void)AtomicWrite(RulesStatsPath(), out.str());
}

void WritePackageStats(const std::vector<PackageStatsSnapshot>& entries) {
  std::vector<PackageStatsSnapshot> sorted = entries;
  std::sort(sorted.begin(), sorted.end(),
            [](const PackageStatsSnapshot& lhs, const PackageStatsSnapshot& rhs) {
              return lhs.package < rhs.package;
            });

  std::ostringstream out;
  out << "{\"version\":1,\"generated_at\":" << UnixNow()
      << ",\"packages\":[";
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    const auto& entry = sorted[i];
    if (i > 0) {
      out << ',';
    }
    out << "{\"package\":\"" << JsonEscape(entry.package)
        << "\",\"matched_total\":" << entry.matched_total
        << ",\"blocked_total\":" << entry.blocked_total
        << ",\"allowed_total\":" << entry.allowed_total
        << ",\"suppressed_total\":" << entry.suppressed_total
        << ",\"modified_total\":" << entry.modified_total
        << ",\"detect_only_total\":" << entry.detect_only_total
        << ",\"error_total\":" << entry.error_total
        << ",\"last_matched_at\":" << entry.last_matched_at
        << ",\"last_blocked_at\":" << entry.last_blocked_at
        << ",\"last_error_at\":" << entry.last_error_at
        << ",\"last_disposition\":\"" << JsonEscape(entry.last_disposition)
        << "\",\"last_project\":\"" << JsonEscape(entry.last_project)
        << "\",\"last_session_id\":\"" << JsonEscape(entry.last_session_id)
        << "\"}";
  }
  out << "]}\n";
  (void)AtomicWrite(PackagesStatsPath(), out.str());
}

RuleStatsSnapshot* FindRuleStats(std::vector<RuleStatsSnapshot>* entries,
                                 int rule_id) {
  if (entries == nullptr) {
    return nullptr;
  }
  for (auto& entry : *entries) {
    if (entry.rule_id == rule_id) {
      return &entry;
    }
  }
  return nullptr;
}

PackageStatsSnapshot* FindPackageStats(
    std::vector<PackageStatsSnapshot>* entries, std::string_view package) {
  if (entries == nullptr) {
    return nullptr;
  }
  for (auto& entry : *entries) {
    if (entry.package == package) {
      return &entry;
    }
  }
  return nullptr;
}

}  // namespace

void UpdateRuleMatchStats(const Transaction& tx, const EvaluatedRule& rule) {
  EnsurePolicyScaffold();

  auto rule_entries = ParseRuleStatsSnapshot();
  auto package_entries = ParsePackageStatsSnapshot();

  const long now = UnixNow();
  const std::string project_root = ProjectRootFromTranscriptPath(tx.transcript_path);
  const std::string disposition = RuleDisposition(rule);

  RuleStatsSnapshot* rule_entry =
      FindRuleStats(&rule_entries, rule.meta.rule_id);
  if (rule_entry == nullptr) {
    rule_entries.push_back({});
    rule_entry = &rule_entries.back();
    rule_entry->rule_id = rule.meta.rule_id;
  }
  rule_entry->package = rule.meta.package;
  rule_entry->rule_name = rule.meta.name;
  rule_entry->phase = std::string(ToString(rule.meta.phase));
  rule_entry->severity = std::string(ToString(rule.meta.severity));
  ++rule_entry->matched_total;
  BumpDispositionCounter(rule_entry, disposition);
  rule_entry->last_disposition = disposition;
  rule_entry->last_matched_at = now;
  if (disposition == "blocked") {
    rule_entry->last_blocked_at = now;
  }
  if (!project_root.empty()) {
    rule_entry->last_project = project_root;
  }
  if (!tx.session_id.empty()) {
    rule_entry->last_session_id = tx.session_id;
  }

  PackageStatsSnapshot* package_entry =
      FindPackageStats(&package_entries, rule.meta.package);
  if (package_entry == nullptr) {
    package_entries.push_back({});
    package_entry = &package_entries.back();
    package_entry->package = rule.meta.package;
  }
  ++package_entry->matched_total;
  BumpDispositionCounter(package_entry, disposition);
  package_entry->last_disposition = disposition;
  package_entry->last_matched_at = now;
  if (disposition == "blocked") {
    package_entry->last_blocked_at = now;
  }
  if (!project_root.empty()) {
    package_entry->last_project = project_root;
  }
  if (!tx.session_id.empty()) {
    package_entry->last_session_id = tx.session_id;
  }

  WriteRuleStats(rule_entries);
  WritePackageStats(package_entries);
}

void UpdateRuleErrorStats(const Transaction& tx, const RuleEngineError& error) {
  EnsurePolicyScaffold();

  auto rule_entries = ParseRuleStatsSnapshot();
  auto package_entries = ParsePackageStatsSnapshot();

  const long now = UnixNow();
  const std::string project_root = ProjectRootFromTranscriptPath(tx.transcript_path);

  RuleStatsSnapshot* rule_entry =
      FindRuleStats(&rule_entries, error.meta.rule_id);
  if (rule_entry == nullptr) {
    rule_entries.push_back({});
    rule_entry = &rule_entries.back();
    rule_entry->rule_id = error.meta.rule_id;
  }
  rule_entry->package = error.meta.package;
  rule_entry->rule_name = error.meta.name;
  rule_entry->phase = std::string(ToString(error.meta.phase));
  rule_entry->severity = std::string(ToString(error.meta.severity));
  ++rule_entry->error_total;
  rule_entry->last_error_at = now;
  if (!project_root.empty()) {
    rule_entry->last_project = project_root;
  }
  if (!tx.session_id.empty()) {
    rule_entry->last_session_id = tx.session_id;
  }

  PackageStatsSnapshot* package_entry =
      FindPackageStats(&package_entries, error.meta.package);
  if (package_entry == nullptr) {
    package_entries.push_back({});
    package_entry = &package_entries.back();
    package_entry->package = error.meta.package;
  }
  ++package_entry->error_total;
  package_entry->last_error_at = now;
  if (!project_root.empty()) {
    package_entry->last_project = project_root;
  }
  if (!tx.session_id.empty()) {
    package_entry->last_session_id = tx.session_id;
  }

  WriteRuleStats(rule_entries);
  WritePackageStats(package_entries);
}

std::vector<RuleStatsSnapshot> LoadRuleStatsSnapshot() {
  EnsurePolicyScaffold();
  return ParseRuleStatsSnapshot();
}

std::vector<PackageStatsSnapshot> LoadPackageStatsSnapshot() {
  EnsurePolicyScaffold();
  return ParsePackageStatsSnapshot();
}

}  // namespace sg
