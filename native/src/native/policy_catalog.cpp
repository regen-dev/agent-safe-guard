#include "sg/policy_catalog.hpp"

#include "sg/json_extract.hpp"
#include "sg/policy_state.hpp"
#include "sg/process.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string_view>
#include <unistd.h>

namespace sg {
namespace {

constexpr std::string_view kOfficialCatalogUrl =
    "https://raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/main/rules/catalogs/github-core.json";
// Any previously pinned tag URL is migrated to kOfficialCatalogUrl on load.
constexpr std::string_view kLegacyTagPrefix =
    "https://raw.githubusercontent.com/regen-dev/agent-safe-guard-rules/rules-v";

struct ParsedCatalogData {
  long catalog_version = 0;
  std::string catalog_id;
  std::string display_name;
  std::string source_url;
  std::vector<CatalogPackageRecord> packages;
};

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

std::string Lower(std::string_view input) {
  std::string out(input);
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return out;
}

bool IsSlugToken(std::string_view raw) {
  if (raw.empty()) {
    return false;
  }
  for (const unsigned char ch : raw) {
    if ((std::isalnum(ch) != 0 && std::tolower(ch) == ch) || ch == '-' ||
        ch == '_' || ch == '.') {
      continue;
    }
    return false;
  }
  return true;
}

bool IsHexSha256(std::string_view raw) {
  if (raw.size() != 64) {
    return false;
  }
  for (const unsigned char ch : raw) {
    if (std::isdigit(ch) != 0) {
      continue;
    }
    const unsigned char lowered = static_cast<unsigned char>(std::tolower(ch));
    if (lowered < 'a' || lowered > 'f') {
      return false;
    }
  }
  return true;
}

bool IsOfficialCatalogSource(std::string_view source_url) {
  return source_url == kOfficialCatalogUrl ||
         source_url.substr(0, kLegacyTagPrefix.size()) == kLegacyTagPrefix;
}

bool StartsWith(std::string_view input, std::string_view prefix) {
  return input.substr(0, prefix.size()) == prefix;
}

bool HasScheme(std::string_view input) {
  return input.find("://") != std::string_view::npos;
}

std::string HumanizeIdentifier(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  bool capitalize = true;
  for (const unsigned char ch : input) {
    if (ch == '_' || ch == '-' || ch == '/' || ch == '.') {
      if (!out.empty() && out.back() != ' ') {
        out.push_back(' ');
      }
      capitalize = true;
      continue;
    }
    if (capitalize) {
      out.push_back(static_cast<char>(std::toupper(ch)));
      capitalize = false;
    } else {
      out.push_back(static_cast<char>(ch));
    }
  }
  return out.empty() ? std::string(input) : out;
}

std::string FileSafeId(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const unsigned char ch : input) {
    if (std::isalnum(ch) != 0) {
      out.push_back(static_cast<char>(std::tolower(ch)));
      continue;
    }
    if (ch == '-' || ch == '_' || ch == '.') {
      out.push_back(static_cast<char>(ch));
      continue;
    }
    out.push_back('-');
  }
  while (!out.empty() && out.back() == '-') {
    out.pop_back();
  }
  if (out.empty()) {
    return "catalog";
  }
  return out;
}

std::string StableHexDigest(std::string_view input) {
  std::uint64_t hash = 1469598103934665603ull;
  for (const unsigned char ch : input) {
    hash ^= static_cast<std::uint64_t>(ch);
    hash *= 1099511628211ull;
  }
  std::ostringstream out;
  out << std::hex << std::setfill('0') << std::setw(16) << hash;
  return out.str();
}

std::string ResolveHttpReference(std::string_view base_source,
                                 std::string_view reference) {
  const std::size_t scheme_sep = base_source.find("://");
  if (scheme_sep == std::string_view::npos) {
    return std::string(reference);
  }

  const std::size_t authority_start = scheme_sep + 3;
  const std::size_t path_start = base_source.find('/', authority_start);
  const std::string origin =
      path_start == std::string_view::npos
          ? std::string(base_source)
          : std::string(base_source.substr(0, path_start));
  std::string path =
      path_start == std::string_view::npos
          ? "/"
          : std::string(base_source.substr(path_start));
  if (const std::size_t trim_at = path.find_first_of("?#");
      trim_at != std::string::npos) {
    path = path.substr(0, trim_at);
  }

  const std::filesystem::path resolved =
      (std::filesystem::path(path).parent_path() / std::string(reference))
          .lexically_normal();
  std::string normalized = resolved.generic_string();
  if (normalized.empty() || normalized.front() != '/') {
    normalized.insert(normalized.begin(), '/');
  }
  return origin + normalized;
}

std::string ResolveSourceReference(std::string_view reference,
                                   std::string_view base_source) {
  const std::string trimmed_reference = Trim(reference);
  if (trimmed_reference.empty()) {
    return "";
  }
  if (StartsWith(trimmed_reference, "https://") ||
      StartsWith(trimmed_reference, "file://")) {
    return trimmed_reference;
  }

  const std::filesystem::path reference_path(trimmed_reference);
  if (reference_path.is_absolute() || base_source.empty()) {
    return reference_path.lexically_normal().string();
  }

  const std::string trimmed_base = Trim(base_source);
  if (StartsWith(trimmed_base, "file://")) {
    const std::filesystem::path base_path(trimmed_base.substr(7));
    return "file://" +
           (base_path.parent_path() / reference_path).lexically_normal().string();
  }
  if (StartsWith(trimmed_base, "https://")) {
    return ResolveHttpReference(trimmed_base, trimmed_reference);
  }
  if (HasScheme(trimmed_base)) {
    return trimmed_reference;
  }

  const std::filesystem::path base_path(trimmed_base);
  return (base_path.parent_path() / reference_path).lexically_normal().string();
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

bool AtomicWrite(const std::filesystem::path& path, const std::string& content,
                 std::string* error) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  if (ec) {
    if (error != nullptr) {
      *error = "create_directories failed: " + ec.message();
    }
    return false;
  }

  const auto tmp =
      path.string() + ".tmp." + std::to_string(static_cast<long long>(::getpid()));
  {
    std::ofstream out(tmp, std::ios::trunc | std::ios::binary);
    if (!out) {
      if (error != nullptr) {
        *error = "open failed: " + tmp;
      }
      return false;
    }
    out << content;
    if (!out) {
      if (error != nullptr) {
        *error = "write failed: " + tmp;
      }
      return false;
    }
  }

  std::filesystem::rename(tmp, path, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    if (error != nullptr) {
      *error = "rename failed: " + ec.message();
    }
    return false;
  }
  return true;
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

std::vector<std::string> SplitJsonStringArray(std::string_view json) {
  std::vector<std::string> out;
  if (json.size() < 2 || json.front() != '[' || json.back() != ']') {
    return out;
  }

  bool in_string = false;
  bool escaped = false;
  std::size_t start = std::string_view::npos;
  for (std::size_t i = 1; i + 1 < json.size(); ++i) {
    const char ch = json[i];
    if (!in_string) {
      if (ch == '"') {
        in_string = true;
        start = i;
      }
      continue;
    }

    if (escaped) {
      escaped = false;
      continue;
    }
    if (ch == '\\') {
      escaped = true;
      continue;
    }
    if (ch == '"') {
      const std::string wrapped = std::string(json.substr(start, i - start + 1));
      if (wrapped.size() >= 2) {
        const auto decoded = FindJsonString("{\"v\":" + wrapped + "}", "v");
        if (decoded.has_value()) {
          out.push_back(*decoded);
        }
      }
      in_string = false;
      start = std::string_view::npos;
    }
  }
  return out;
}

RulePhase ParseRulePhase(std::string_view raw) {
  const std::string phase = Trim(raw);
  if (phase == "pre_tool_use") {
    return RulePhase::kPreToolUse;
  }
  if (phase == "post_tool_use") {
    return RulePhase::kPostToolUse;
  }
  if (phase == "permission_request") {
    return RulePhase::kPermissionRequest;
  }
  if (phase == "read_compress") {
    return RulePhase::kReadCompress;
  }
  if (phase == "read_guard") {
    return RulePhase::kReadGuard;
  }
  if (phase == "stop") {
    return RulePhase::kStop;
  }
  if (phase == "session_start") {
    return RulePhase::kSessionStart;
  }
  if (phase == "session_end") {
    return RulePhase::kSessionEnd;
  }
  if (phase == "pre_compact") {
    return RulePhase::kPreCompact;
  }
  if (phase == "subagent_start") {
    return RulePhase::kSubagentStart;
  }
  if (phase == "subagent_stop") {
    return RulePhase::kSubagentStop;
  }
  if (phase == "tool_error") {
    return RulePhase::kToolError;
  }
  return RulePhase::kUnknown;
}

RuleSeverity ParseRuleSeverity(std::string_view raw) {
  const std::string severity = Trim(raw);
  if (severity == "info") {
    return RuleSeverity::kInfo;
  }
  if (severity == "low") {
    return RuleSeverity::kLow;
  }
  if (severity == "medium") {
    return RuleSeverity::kMedium;
  }
  if (severity == "high") {
    return RuleSeverity::kHigh;
  }
  if (severity == "critical") {
    return RuleSeverity::kCritical;
  }
  return RuleSeverity::kMedium;
}

bool IsKnownRulePhaseToken(std::string_view raw) {
  return ParseRulePhase(raw) != RulePhase::kUnknown;
}

bool IsKnownRuleSeverityToken(std::string_view raw) {
  const std::string severity = Trim(raw);
  return severity == "info" || severity == "low" || severity == "medium" ||
         severity == "high" || severity == "critical";
}

std::vector<std::filesystem::path> CandidateCatalogDirs() {
  std::vector<std::filesystem::path> dirs;
  std::set<std::string> seen;
  const auto add = [&](const std::filesystem::path& path) {
    if (path.empty()) {
      return;
    }
    const std::string normalized = path.lexically_normal().string();
    if (seen.insert(normalized).second) {
      dirs.push_back(path);
    }
  };

  const auto installed = DefaultInstalledPackagesDir();
  add(installed);
  add(installed / "core");

  if (const char* env = std::getenv("SG_RULES_DIR");
      env != nullptr && *env != '\0') {
    const std::filesystem::path root(env);
    add(root);
    add(root / "core");
    add(root / "rules");
    add(root / "rules/core");
  }
  return dirs;
}

std::vector<std::filesystem::path> CandidateManifestFiles() {
  std::vector<std::filesystem::path> files;
  std::set<std::string> seen;

  for (const auto& dir : CandidateCatalogDirs()) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || ec ||
        !std::filesystem::is_directory(dir, ec)) {
      continue;
    }

    std::vector<std::filesystem::path> dir_files;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
      if (ec) {
        break;
      }
      if (!entry.is_regular_file()) {
        continue;
      }
      if (entry.path().extension() != ".json") {
        continue;
      }
      dir_files.push_back(entry.path());
    }
    std::sort(dir_files.begin(), dir_files.end());
    for (const auto& file : dir_files) {
      const std::string normalized = file.lexically_normal().string();
      if (seen.insert(normalized).second) {
        files.push_back(file);
      }
    }
  }
  return files;
}

bool ParseRuleObject(std::string_view rule_obj, std::string_view package_name,
                     RuleMetadata* out_rule, std::string* error) {
  if (out_rule == nullptr) {
    if (error != nullptr) {
      *error = "rule parser received null output";
    }
    return false;
  }

  const auto raw_rule_id = FindJsonRaw(rule_obj, "rule_id");
  const long parsed_rule_id =
      ParseLong(raw_rule_id.value_or("0")).value_or(0);
  if (parsed_rule_id <= 0) {
    if (error != nullptr) {
      *error = "rule is missing a positive rule_id";
    }
    return false;
  }

  const std::string name = FindJsonString(rule_obj, "name").value_or("");
  if (name.empty()) {
    if (error != nullptr) {
      *error = "rule " + std::to_string(parsed_rule_id) + " is missing name";
    }
    return false;
  }

  const std::string phase = FindJsonString(rule_obj, "phase").value_or("");
  if (!IsKnownRulePhaseToken(phase)) {
    if (error != nullptr) {
      *error = "rule " + std::to_string(parsed_rule_id) +
               " has invalid phase: " + (phase.empty() ? "<empty>" : phase);
    }
    return false;
  }

  const std::string severity =
      FindJsonString(rule_obj, "severity").value_or("medium");
  if (!IsKnownRuleSeverityToken(severity)) {
    if (error != nullptr) {
      *error = "rule " + std::to_string(parsed_rule_id) +
               " has invalid severity: " + severity;
    }
    return false;
  }

  out_rule->rule_id = static_cast<int>(parsed_rule_id);
  out_rule->package = std::string(package_name);
  out_rule->name = name;
  out_rule->description =
      FindJsonString(rule_obj, "description").value_or("");
  out_rule->phase = ParseRulePhase(phase);
  out_rule->severity = ParseRuleSeverity(severity);
  // Catalog rule matching fields (optional — empty for metadata-only rules).
  out_rule->match_tool =
      FindJsonString(rule_obj, "match_tool").value_or("");
  out_rule->match_field =
      FindJsonString(rule_obj, "match_field").value_or("");
  out_rule->pattern =
      FindJsonString(rule_obj, "pattern").value_or("");
  out_rule->action_str =
      FindJsonString(rule_obj, "action").value_or("");
  out_rule->message =
      FindJsonString(rule_obj, "message").value_or("");
  return true;
}

bool ParseRules(std::string_view rules_json, std::string_view package_name,
                std::vector<RuleMetadata>* out_rules, std::string* error) {
  if (out_rules == nullptr) {
    if (error != nullptr) {
      *error = "rule parser received null output collection";
    }
    return false;
  }

  const auto rule_objects = SplitJsonObjectArray(rules_json);
  if (rule_objects.empty()) {
    if (error != nullptr) {
      *error = "rules must be a non-empty array of rule objects";
    }
    return false;
  }

  std::set<int> seen_rule_ids;
  std::vector<RuleMetadata> rules;
  for (const auto& rule_obj : rule_objects) {
    RuleMetadata rule;
    if (!ParseRuleObject(rule_obj, package_name, &rule, error)) {
      return false;
    }
    if (!seen_rule_ids.insert(rule.rule_id).second) {
      if (error != nullptr) {
        *error = "rules array reuses rule_id " + std::to_string(rule.rule_id);
      }
      return false;
    }
    rules.push_back(std::move(rule));
  }

  *out_rules = std::move(rules);
  return true;
}

std::optional<PackageCatalogEntry> ParseManifestRaw(
    std::string_view raw, const std::string& source_label, std::string* error) {
  if (raw.empty()) {
    if (error != nullptr) {
      *error = "manifest is empty";
    }
    return std::nullopt;
  }

  PackageCatalogEntry entry;
  entry.package = FindJsonString(raw, "package_id")
                      .value_or(FindJsonString(raw, "package").value_or(""));
  if (entry.package.empty()) {
    if (error != nullptr) {
      *error = "manifest missing package";
    }
    return std::nullopt;
  }
  if (!IsSlugToken(entry.package)) {
    if (error != nullptr) {
      *error = "manifest package must be a lowercase slug: " + entry.package;
    }
    return std::nullopt;
  }

  entry.version = FindJsonString(raw, "package_version")
                      .value_or(FindJsonString(raw, "version").value_or(""));
  if (entry.version.empty()) {
    if (error != nullptr) {
      *error = "manifest " + entry.package + " missing version";
    }
    return std::nullopt;
  }
  entry.title =
      FindJsonString(raw, "display_name")
          .value_or(FindJsonString(raw, "title")
                        .value_or(HumanizeIdentifier(entry.package)));
  entry.summary = FindJsonString(raw, "description")
                      .value_or(FindJsonString(raw, "summary").value_or(""));
  entry.category = FindJsonString(raw, "category").value_or("External");
  entry.source_path = source_label;

  const auto rules_array = FindJsonRaw(raw, "rules");
  if (!rules_array.has_value()) {
    if (error != nullptr) {
      *error = "manifest " + entry.package + " missing rules array";
    }
    return std::nullopt;
  }
  if (!ParseRules(*rules_array, entry.package, &entry.rules, error)) {
    return std::nullopt;
  }

  return entry;
}

std::optional<PackageCatalogEntry> ParseManifest(
    const std::filesystem::path& path) {
  std::string ignored_error;
  return ParseManifestRaw(ReadFile(path), path.string(), &ignored_error);
}

std::optional<InstalledPackageRecord> ParseInstalledRecord(
    std::string_view json) {
  InstalledPackageRecord record;
  record.package = FindJsonString(json, "package").value_or("");
  if (record.package.empty()) {
    return std::nullopt;
  }
  record.version = FindJsonString(json, "version").value_or("");
  record.source_path = FindJsonString(json, "source_path").value_or("");
  record.source_url = FindJsonString(json, "source_url").value_or("");
  record.catalog_id = FindJsonString(json, "catalog_id").value_or("");
  record.download_url = FindJsonString(json, "download_url").value_or("");
  record.sha256 = Lower(FindJsonString(json, "sha256").value_or(""));
  record.installed_path = FindJsonString(json, "installed_path").value_or("");
  record.installed_at =
      ParseLong(FindJsonRaw(json, "installed_at").value_or("0")).value_or(0);
  return record;
}

std::optional<CatalogSourceRecord> ParseCatalogSourceRecord(
    std::string_view json) {
  CatalogSourceRecord record;
  record.catalog_id = FindJsonString(json, "catalog_id").value_or("");
  record.display_name = FindJsonString(json, "display_name").value_or("");
  record.source_url = FindJsonString(json, "source_url").value_or("");
  if (record.source_url.empty()) {
    return std::nullopt;
  }
  record.cache_path = FindJsonString(json, "cache_path").value_or("");
  record.added_at =
      ParseLong(FindJsonRaw(json, "added_at").value_or("0")).value_or(0);
  record.last_synced_at =
      ParseLong(FindJsonRaw(json, "last_synced_at").value_or("0")).value_or(0);
  return record;
}

std::filesystem::path CachePathForSource(std::string_view source_url) {
  return DefaultCatalogCacheDir() /
         (FileSafeId(source_url.substr(0, std::min<std::size_t>(32, source_url.size()))) +
          "-" + StableHexDigest(source_url) + ".json");
}

std::filesystem::path PackageCachePathForRecord(const CatalogPackageRecord& record) {
  const std::string stem =
      FileSafeId(record.catalog_id.empty() ? "catalog" : record.catalog_id) + "__" +
      FileSafeId(record.package) + "@" +
      FileSafeId(record.version.empty() ? "latest" : record.version);
  return DefaultCatalogCacheDir() / "packages" / (stem + ".json");
}

bool ValidateManifestEntry(const PackageCatalogEntry& entry, std::string* error) {
  if (entry.package.empty()) {
    if (error != nullptr) {
      *error = "manifest missing package";
    }
    return false;
  }
  if (entry.rules.empty()) {
    if (error != nullptr) {
      *error = "manifest has no rules";
    }
    return false;
  }
  if (entry.version.empty()) {
    if (error != nullptr) {
      *error = "manifest " + entry.package + " is missing version";
    }
    return false;
  }

  std::set<int> seen_rule_ids;
  for (const auto& rule : entry.rules) {
    if (rule.rule_id == 0) {
      if (error != nullptr) {
        *error = "manifest contains rule with empty rule_id";
      }
      return false;
    }
    if (rule.name.empty()) {
      if (error != nullptr) {
        *error = "manifest contains rule with empty name";
      }
      return false;
    }
    if (rule.phase == RulePhase::kUnknown) {
      if (error != nullptr) {
        *error = "manifest contains rule with unknown phase";
      }
      return false;
    }
    if (!seen_rule_ids.insert(rule.rule_id).second) {
      if (error != nullptr) {
        *error = "manifest reuses rule_id " + std::to_string(rule.rule_id);
      }
      return false;
    }
  }
  return true;
}

bool ValidateCatalogData(const ParsedCatalogData& catalog, std::string* error) {
  if (catalog.catalog_version != 1) {
    if (error != nullptr) {
      *error = "catalog_version must be 1";
    }
    return false;
  }
  if (catalog.catalog_id.empty()) {
    if (error != nullptr) {
      *error = "catalog missing catalog_id";
    }
    return false;
  }
  if (!IsSlugToken(catalog.catalog_id)) {
    if (error != nullptr) {
      *error = "catalog_id must be a lowercase slug: " + catalog.catalog_id;
    }
    return false;
  }
  if (catalog.packages.empty()) {
    if (error != nullptr) {
      *error = "catalog has no packages";
    }
    return false;
  }

  std::set<std::string> seen_packages;
  std::set<int> seen_rule_ids;
  for (const auto& package : catalog.packages) {
    if (package.package.empty()) {
      if (error != nullptr) {
        *error = "catalog contains package with empty package_id";
      }
      return false;
    }
    if (!IsSlugToken(package.package)) {
      if (error != nullptr) {
        *error = "catalog package_id must be a lowercase slug: " + package.package;
      }
      return false;
    }
    if (package.version.empty()) {
      if (error != nullptr) {
        *error = "catalog package " + package.package +
                 " is missing package_version";
      }
      return false;
    }
    if (package.download_url.empty()) {
      if (error != nullptr) {
        *error = "catalog package " + package.package +
                 " is missing download_url";
      }
      return false;
    }
    if (package.sha256.empty()) {
      if (error != nullptr) {
        *error = "catalog package " + package.package + " is missing sha256";
      }
      return false;
    }
    if (!IsHexSha256(package.sha256)) {
      if (error != nullptr) {
        *error = "catalog package " + package.package +
                 " has invalid sha256";
      }
      return false;
    }
    if (package.phases.empty()) {
      if (error != nullptr) {
        *error = "catalog package " + package.package +
                 " is missing non-empty phases";
      }
      return false;
    }
    for (const auto& phase : package.phases) {
      if (!IsKnownRulePhaseToken(phase)) {
        if (error != nullptr) {
          *error = "catalog package " + package.package +
                   " has invalid phase entry: " + phase;
        }
        return false;
      }
    }
    if (package.rules.empty()) {
      if (error != nullptr) {
        *error = "catalog package " + package.package +
                 " is missing non-empty rules";
      }
      return false;
    }
    for (const auto& rule : package.rules) {
      if (!seen_rule_ids.insert(rule.rule_id).second) {
        if (error != nullptr) {
          *error = "catalog reuses rule_id " + std::to_string(rule.rule_id);
        }
        return false;
      }
      if (std::find(package.phases.begin(), package.phases.end(),
                    std::string(ToString(rule.phase))) == package.phases.end()) {
        if (error != nullptr) {
          *error = "catalog package " + package.package +
                   " omits rule phase from phases list for rule_id " +
                   std::to_string(rule.rule_id);
        }
        return false;
      }
    }
    if (!seen_packages.insert(package.package).second) {
      if (error != nullptr) {
        *error = "catalog reuses package_id " + package.package;
      }
      return false;
    }
  }
  return true;
}

std::optional<ParsedCatalogData> ParseCatalogData(
    std::string_view raw, std::string_view default_source_url,
    std::string* error) {
  if (raw.empty()) {
    if (error != nullptr) {
      *error = "catalog is empty";
    }
    return std::nullopt;
  }

  ParsedCatalogData catalog;
  catalog.catalog_version =
      ParseLong(FindJsonRaw(raw, "catalog_version").value_or("0")).value_or(0);
  catalog.catalog_id = FindJsonString(raw, "catalog_id")
                           .value_or("catalog-" + StableHexDigest(default_source_url));
  catalog.display_name = FindJsonString(raw, "display_name")
                             .value_or(HumanizeIdentifier(catalog.catalog_id));
  catalog.source_url = ResolveSourceReference(
      FindJsonString(raw, "source_url").value_or(""), default_source_url);
  if (catalog.source_url.empty()) {
    catalog.source_url = std::string(default_source_url);
  }

  const auto packages_array = FindJsonRaw(raw, "packages");
  if (!packages_array.has_value()) {
    if (error != nullptr) {
      *error = "catalog missing packages array";
    }
    return std::nullopt;
  }

  for (const auto& package_obj : SplitJsonObjectArray(*packages_array)) {
    CatalogPackageRecord package;
    package.catalog_id = catalog.catalog_id;
    package.catalog_title = catalog.display_name;
    package.catalog_source_url = catalog.source_url;
    package.package =
        FindJsonString(package_obj, "package_id")
            .value_or(FindJsonString(package_obj, "package").value_or(""));
    if (package.package.empty()) {
      if (error != nullptr) {
        *error = "catalog package missing package_id";
      }
      return std::nullopt;
    }

    package.version = FindJsonString(package_obj, "package_version")
                          .value_or(FindJsonString(package_obj, "version").value_or(""));
    package.title = FindJsonString(package_obj, "display_name")
                        .value_or(FindJsonString(package_obj, "title")
                                      .value_or(HumanizeIdentifier(package.package)));
    package.summary = FindJsonString(package_obj, "description")
                          .value_or(FindJsonString(package_obj, "summary").value_or(""));
    package.download_url = ResolveSourceReference(
        FindJsonString(package_obj, "download_url").value_or(""),
        catalog.source_url.empty() ? std::string(default_source_url)
                                   : catalog.source_url);
    package.sha256 = Lower(FindJsonString(package_obj, "sha256").value_or(""));

    if (const auto tags = FindJsonRaw(package_obj, "tags"); tags.has_value()) {
      package.tags = SplitJsonStringArray(*tags);
    }
    if (const auto phases = FindJsonRaw(package_obj, "phases");
        phases.has_value()) {
      package.phases = SplitJsonStringArray(*phases);
    }
    const auto rules = FindJsonRaw(package_obj, "rules");
    if (!rules.has_value()) {
      if (error != nullptr) {
        *error = "catalog package " + package.package + " missing rules array";
      }
      return std::nullopt;
    }
    if (!ParseRules(*rules, package.package, &package.rules, error)) {
      if (error != nullptr) {
        *error = "catalog package " + package.package + ": " + *error;
      }
      return std::nullopt;
    }

    catalog.packages.push_back(std::move(package));
  }

  return catalog;
}

bool WriteInstalledState(const std::vector<InstalledPackageRecord>& records,
                         std::string* error) {
  std::vector<InstalledPackageRecord> sorted = records;
  std::sort(sorted.begin(), sorted.end(),
            [](const InstalledPackageRecord& lhs,
               const InstalledPackageRecord& rhs) {
              return lhs.package < rhs.package;
            });

  std::ostringstream out;
  out << "{\"version\":1,\"installed\":[";
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    if (i > 0) {
      out << ',';
    }
    out << "{\"package\":\"" << JsonEscape(sorted[i].package)
        << "\",\"version\":\"" << JsonEscape(sorted[i].version)
        << "\",\"source_path\":\"" << JsonEscape(sorted[i].source_path)
        << "\",\"source_url\":\"" << JsonEscape(sorted[i].source_url)
        << "\",\"catalog_id\":\"" << JsonEscape(sorted[i].catalog_id)
        << "\",\"download_url\":\"" << JsonEscape(sorted[i].download_url)
        << "\",\"sha256\":\"" << JsonEscape(sorted[i].sha256)
        << "\",\"installed_path\":\"" << JsonEscape(sorted[i].installed_path)
        << "\",\"installed_at\":" << sorted[i].installed_at << "}";
  }
  out << "]}\n";
  return AtomicWrite(DefaultInstalledStatePath(), out.str(), error);
}

bool WriteCatalogState(const std::vector<CatalogSourceRecord>& records,
                       std::string* error) {
  std::vector<CatalogSourceRecord> sorted = records;
  std::sort(sorted.begin(), sorted.end(),
            [](const CatalogSourceRecord& lhs, const CatalogSourceRecord& rhs) {
              if (lhs.display_name != rhs.display_name) {
                return lhs.display_name < rhs.display_name;
              }
              return lhs.source_url < rhs.source_url;
            });

  std::ostringstream out;
  out << "{\"version\":1,\"catalogs\":[";
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    if (i > 0) {
      out << ',';
    }
    out << "{\"catalog_id\":\"" << JsonEscape(sorted[i].catalog_id)
        << "\",\"display_name\":\"" << JsonEscape(sorted[i].display_name)
        << "\",\"source_url\":\"" << JsonEscape(sorted[i].source_url)
        << "\",\"cache_path\":\"" << JsonEscape(sorted[i].cache_path)
        << "\",\"added_at\":" << sorted[i].added_at
        << ",\"last_synced_at\":" << sorted[i].last_synced_at << "}";
  }
  out << "]}\n";
  return AtomicWrite(DefaultCatalogsStatePath(), out.str(), error);
}

std::string DefaultCatalogDisplayName(std::string_view source_url) {
  if (IsOfficialCatalogSource(source_url)) {
    return "GitHub Core Catalog";
  }
  return "Default Catalog";
}

std::string DefaultCatalogId(std::string_view source_url) {
  if (IsOfficialCatalogSource(source_url)) {
    return "github-core";
  }
  return "";
}

bool MigrateOfficialCatalogSources(std::vector<CatalogSourceRecord>* records,
                                   std::string* error) {
  if (records == nullptr) {
    return true;
  }

  bool mutated = false;
  for (auto& record : *records) {
    if (record.source_url == kOfficialCatalogUrl) {
      continue;  // Already current.
    }
    if (!IsOfficialCatalogSource(record.source_url)) {
      continue;  // Not ours — leave it alone.
    }
    record.source_url = std::string(kOfficialCatalogUrl);
    record.cache_path = CachePathForSource(record.source_url).string();
    if (record.catalog_id.empty()) {
      record.catalog_id = "github-core";
    }
    if (record.display_name.empty()) {
      record.display_name = "GitHub Core Catalog";
    }
    mutated = true;
  }

  if (!mutated) {
    return true;
  }
  return WriteCatalogState(*records, error);
}

bool InstallPackageManifestRaw(std::string_view raw,
                               const InstalledPackageRecord& base_record,
                               std::string* error) {
  std::string parse_error;
  const auto manifest = ParseManifestRaw(
      raw, base_record.source_path.empty() ? base_record.download_url
                                           : base_record.source_path,
      &parse_error);
  if (!manifest.has_value()) {
    if (error != nullptr) {
      *error = parse_error.empty() ? "invalid package manifest" : parse_error;
    }
    return false;
  }
  if (!ValidateManifestEntry(*manifest, error)) {
    return false;
  }
  if (!base_record.package.empty() && manifest->package != base_record.package) {
    if (error != nullptr) {
      *error = "manifest package mismatch: expected " + base_record.package +
               ", got " + manifest->package;
    }
    return false;
  }
  if (!base_record.version.empty() && !manifest->version.empty() &&
      manifest->version != base_record.version) {
    if (error != nullptr) {
      *error = "manifest version mismatch: expected " + base_record.version +
               ", got " + manifest->version;
    }
    return false;
  }

  const auto install_path =
      DefaultInstalledPackagesDir() / (manifest->package + std::string(".json"));
  if (!AtomicWrite(install_path, std::string(raw), error)) {
    return false;
  }

  auto records = LoadInstalledPackageRecords();
  auto it = std::find_if(records.begin(), records.end(),
                         [&](const InstalledPackageRecord& record) {
                           return record.package == manifest->package;
                         });

  InstalledPackageRecord record = base_record;
  record.package = manifest->package;
  if (record.version.empty()) {
    record.version = manifest->version;
  }
  record.installed_path = install_path.lexically_normal().string();
  record.installed_at = static_cast<long>(std::time(nullptr));

  if (it == records.end()) {
    records.push_back(std::move(record));
  } else {
    *it = std::move(record);
  }

  return WriteInstalledState(records, error);
}

bool FetchTextFromSource(std::string_view source, std::string* out_text,
                         std::string* error) {
  const std::string trimmed = Trim(source);
  if (trimmed.empty()) {
    if (error != nullptr) {
      *error = "source is empty";
    }
    return false;
  }

  if (StartsWith(trimmed, "file://")) {
    const std::filesystem::path path(trimmed.substr(7));
    const std::string raw = ReadFile(path);
    if (raw.empty()) {
      if (error != nullptr) {
        *error = "failed to read file source: " + path.string();
      }
      return false;
    }
    if (out_text != nullptr) {
      *out_text = raw;
    }
    return true;
  }

  const std::filesystem::path maybe_path(trimmed);
  std::error_code ec;
  if (std::filesystem::exists(maybe_path, ec) && !ec) {
    const std::string raw = ReadFile(maybe_path);
    if (raw.empty()) {
      if (error != nullptr) {
        *error = "failed to read local source: " + maybe_path.string();
      }
      return false;
    }
    if (out_text != nullptr) {
      *out_text = raw;
    }
    return true;
  }

  if (!StartsWith(trimmed, "https://")) {
    if (error != nullptr) {
      *error = "unsupported catalog source: " + trimmed;
    }
    return false;
  }

  const ProcessResult result = RunProcess({"curl", "-fsSL", trimmed});
  if (result.exit_code != 0) {
    if (error != nullptr) {
      *error = "curl failed for " + trimmed + ": " + Trim(result.stderr_text);
    }
    return false;
  }
  if (out_text != nullptr) {
    *out_text = result.stdout_text;
  }
  return true;
}

std::optional<std::string> ComputeSha256(
    const std::filesystem::path& path, std::string* error) {
  const ProcessResult result =
      RunProcess({"sha256sum", path.lexically_normal().string()});
  if (result.exit_code != 0) {
    if (error != nullptr) {
      *error =
          "sha256sum failed for " + path.string() + ": " + Trim(result.stderr_text);
    }
    return std::nullopt;
  }
  const std::string output = Trim(result.stdout_text);
  if (output.empty()) {
    if (error != nullptr) {
      *error = "sha256sum returned empty output for " + path.string();
    }
    return std::nullopt;
  }
  const auto split = output.find_first_of(" \t");
  return Lower(split == std::string::npos ? output : output.substr(0, split));
}

std::optional<CatalogPackageRecord> ResolveCatalogPackage(
    std::string_view selector, std::string* error) {
  std::string catalog_id;
  std::string package = Trim(selector);
  const auto sep = package.find(':');
  if (sep != std::string::npos) {
    catalog_id = package.substr(0, sep);
    package = package.substr(sep + 1);
  }

  std::vector<CatalogPackageRecord> matches;
  for (const auto& candidate : LoadCatalogPackageRecords()) {
    if (!catalog_id.empty() && candidate.catalog_id != catalog_id) {
      continue;
    }
    if (candidate.package == package) {
      matches.push_back(candidate);
    }
  }

  if (matches.empty()) {
    if (error != nullptr) {
      *error = "catalog package not found: " + std::string(selector);
    }
    return std::nullopt;
  }
  if (matches.size() > 1) {
    if (error != nullptr) {
      *error = "catalog package is ambiguous, use catalog_id:package_id for " +
               std::string(selector);
    }
    return std::nullopt;
  }
  return matches.front();
}

}  // namespace

std::filesystem::path DefaultInstalledPackagesDir() {
  return DefaultPolicyDir() / "installed";
}

std::filesystem::path DefaultInstalledStatePath() {
  return DefaultPolicyDir() / "installed.json";
}

std::filesystem::path DefaultCatalogsStatePath() {
  return DefaultPolicyDir() / "catalogs.json";
}

std::filesystem::path DefaultCatalogCacheDir() {
  return DefaultPolicyDir() / "catalogs";
}

std::string DefaultCatalogSourceUrl() {
  if (const char* env = std::getenv("SG_DEFAULT_CATALOG_URL");
      env != nullptr && *env != '\0') {
    return Trim(env);
  }
  return std::string(kOfficialCatalogUrl);
}

void EnsureCatalogStateScaffold() {
  std::error_code ec;
  std::filesystem::create_directories(DefaultPolicyDir(), ec);
  if (std::filesystem::exists(DefaultCatalogsStatePath(), ec) && !ec) {
    return;
  }

  const std::string source_url = DefaultCatalogSourceUrl();
  CatalogSourceRecord record;
  record.catalog_id = DefaultCatalogId(source_url);
  record.display_name = DefaultCatalogDisplayName(source_url);
  record.source_url = source_url;
  record.cache_path = CachePathForSource(source_url).string();
  record.added_at = static_cast<long>(std::time(nullptr));

  std::string ignored_error;
  (void)WriteCatalogState({record}, &ignored_error);

  // Best-effort initial sync so packages are available immediately.
  // Failure is non-fatal (e.g. no network at install time).
  (void)SyncCatalogSources(nullptr);
}

std::vector<PackageCatalogEntry> LoadExternalPackageCatalog() {
  std::map<std::string, PackageCatalogEntry> packages_by_name;
  for (const auto& file : CandidateManifestFiles()) {
    const auto parsed = ParseManifest(file);
    if (!parsed.has_value()) {
      continue;
    }
    packages_by_name[parsed->package] = *parsed;
  }

  std::vector<PackageCatalogEntry> packages;
  for (auto& [_, entry] : packages_by_name) {
    packages.push_back(std::move(entry));
  }
  return packages;
}

std::vector<InstalledPackageRecord> LoadInstalledPackageRecords() {
  std::vector<InstalledPackageRecord> records;
  const std::string raw = ReadFile(DefaultInstalledStatePath());
  const auto array = FindJsonRaw(raw, "installed");
  if (!array.has_value()) {
    return records;
  }

  for (const auto& obj : SplitJsonObjectArray(*array)) {
    const auto record = ParseInstalledRecord(obj);
    if (record.has_value()) {
      records.push_back(*record);
    }
  }
  return records;
}

std::vector<CatalogSourceRecord> LoadCatalogSourceRecords() {
  EnsureCatalogStateScaffold();
  std::vector<CatalogSourceRecord> records;
  const std::string raw = ReadFile(DefaultCatalogsStatePath());
  const auto array = FindJsonRaw(raw, "catalogs");
  if (!array.has_value()) {
    return records;
  }

  for (const auto& obj : SplitJsonObjectArray(*array)) {
    auto record = ParseCatalogSourceRecord(obj);
    if (record.has_value()) {
      if (record->cache_path.empty()) {
        record->cache_path = CachePathForSource(record->source_url).string();
      }
      records.push_back(*record);
    }
  }
  if (const char* override = std::getenv("SG_DEFAULT_CATALOG_URL");
      (override == nullptr || *override == '\0') && !records.empty()) {
    std::string ignored_error;
    (void)MigrateOfficialCatalogSources(&records, &ignored_error);
  }
  return records;
}

std::vector<CatalogPackageRecord> LoadCatalogPackageRecords() {
  std::map<std::string, CatalogPackageRecord> packages_by_key;
  for (const auto& source : LoadCatalogSourceRecords()) {
    const std::filesystem::path cache_path =
        source.cache_path.empty() ? CachePathForSource(source.source_url)
                                  : std::filesystem::path(source.cache_path);
    std::string parse_error;
    const auto parsed =
        ParseCatalogData(ReadFile(cache_path), source.source_url, &parse_error);
    if (!parsed.has_value()) {
      continue;
    }

    for (auto package : parsed->packages) {
      if (package.catalog_id.empty()) {
        package.catalog_id = source.catalog_id;
      }
      if (package.catalog_title.empty()) {
        package.catalog_title = source.display_name;
      }
      const std::string key = package.catalog_id + "\n" + package.package;
      packages_by_key[key] = std::move(package);
    }
  }

  std::vector<CatalogPackageRecord> packages;
  for (auto& [_, entry] : packages_by_key) {
    packages.push_back(std::move(entry));
  }
  std::sort(packages.begin(), packages.end(),
            [](const CatalogPackageRecord& lhs,
               const CatalogPackageRecord& rhs) {
              if (lhs.catalog_id != rhs.catalog_id) {
                return lhs.catalog_id < rhs.catalog_id;
              }
              return lhs.package < rhs.package;
            });
  return packages;
}

bool AddCatalogSource(std::string_view source_url, std::string* error) {
  CatalogSourceRecord record;
  record.source_url = Trim(source_url);
  if (record.source_url.empty()) {
    if (error != nullptr) {
      *error = "catalog source URL is required";
    }
    return false;
  }

  auto records = LoadCatalogSourceRecords();
  const auto existing =
      std::find_if(records.begin(), records.end(),
                   [&](const CatalogSourceRecord& item) {
                     return item.source_url == record.source_url;
                   });
  if (existing != records.end()) {
    if (error != nullptr) {
      *error = "catalog already exists: " + record.source_url;
    }
    return false;
  }

  record.cache_path = CachePathForSource(record.source_url).string();
  record.added_at = static_cast<long>(std::time(nullptr));
  records.push_back(std::move(record));
  return WriteCatalogState(records, error);
}

bool SyncCatalogSources(std::string* error) {
  auto records = LoadCatalogSourceRecords();
  if (records.empty()) {
    if (error != nullptr) {
      *error = "no catalogs configured";
    }
    return false;
  }

  std::vector<std::string> errors;
  for (auto& record : records) {
    std::string raw;
    std::string fetch_error;
    if (!FetchTextFromSource(record.source_url, &raw, &fetch_error)) {
      errors.push_back(fetch_error);
      continue;
    }

    std::string parse_error;
    const auto parsed = ParseCatalogData(raw, record.source_url, &parse_error);
    std::string validation_error;
    if (!parsed.has_value() || !ValidateCatalogData(*parsed, &validation_error)) {
      errors.push_back("catalog sync failed for " + record.source_url + ": " +
                       (!validation_error.empty()
                            ? validation_error
                            : (parse_error.empty() ? "invalid catalog JSON"
                                                   : parse_error)));
      continue;
    }

    const std::filesystem::path cache_path =
        record.cache_path.empty() ? CachePathForSource(record.source_url)
                                  : std::filesystem::path(record.cache_path);
    std::string write_error;
    if (!AtomicWrite(cache_path, raw, &write_error)) {
      errors.push_back("catalog sync failed for " + record.source_url + ": " +
                       write_error);
      continue;
    }

    record.catalog_id = parsed->catalog_id;
    record.display_name = parsed->display_name;
    record.cache_path = cache_path.string();
    record.last_synced_at = static_cast<long>(std::time(nullptr));
  }

  std::string write_error;
  if (!WriteCatalogState(records, &write_error)) {
    if (error != nullptr) {
      *error = write_error;
    }
    return false;
  }

  if (!errors.empty()) {
    if (error != nullptr) {
      std::ostringstream out;
      for (std::size_t i = 0; i < errors.size(); ++i) {
        if (i > 0) {
          out << "; ";
        }
        out << errors[i];
      }
      *error = out.str();
    }
    return false;
  }
  return true;
}

bool InstallCatalogPackage(std::string_view selector, std::string* error) {
  const auto record = ResolveCatalogPackage(selector, error);
  if (!record.has_value()) {
    return false;
  }

  std::string raw;
  std::string fetch_error;
  if (!FetchTextFromSource(record->download_url, &raw, &fetch_error)) {
    if (error != nullptr) {
      *error = fetch_error;
    }
    return false;
  }

  const std::filesystem::path cache_path = PackageCachePathForRecord(*record);
  std::string write_error;
  if (!AtomicWrite(cache_path, raw, &write_error)) {
    if (error != nullptr) {
      *error = write_error;
    }
    return false;
  }

  std::string hash_error;
  const auto sha256 = ComputeSha256(cache_path, &hash_error);
  if (!sha256.has_value()) {
    if (error != nullptr) {
      *error = hash_error;
    }
    return false;
  }
  if (*sha256 != Lower(record->sha256)) {
    if (error != nullptr) {
      *error = "sha256 mismatch for " + record->package + ": expected " +
               Lower(record->sha256) + ", got " + *sha256;
    }
    return false;
  }

  InstalledPackageRecord installed;
  installed.package = record->package;
  installed.version = record->version;
  installed.source_path = cache_path.lexically_normal().string();
  installed.source_url = record->catalog_source_url;
  installed.catalog_id = record->catalog_id;
  installed.download_url = record->download_url;
  installed.sha256 = *sha256;
  return InstallPackageManifestRaw(raw, installed, error);
}

bool InstallPackageManifestFile(const std::filesystem::path& source_path,
                                std::string* error) {
  const std::string raw = ReadFile(source_path);
  if (raw.empty()) {
    if (error != nullptr) {
      *error = "failed to read manifest: " + source_path.string();
    }
    return false;
  }

  InstalledPackageRecord record;
  record.source_path = source_path.lexically_normal().string();
  return InstallPackageManifestRaw(raw, record, error);
}

bool RemoveInstalledPackage(std::string_view package_name, std::string* error) {
  const std::string package(package_name);
  if (package.empty()) {
    if (error != nullptr) {
      *error = "package name is required";
    }
    return false;
  }

  auto records = LoadInstalledPackageRecords();
  const auto before = records.size();
  records.erase(std::remove_if(records.begin(), records.end(),
                               [&](const InstalledPackageRecord& record) {
                                 return record.package == package;
                               }),
                records.end());

  if (before == records.size()) {
    if (error != nullptr) {
      *error = "package is not installed: " + package;
    }
    return false;
  }

  std::error_code ec;
  std::filesystem::remove(DefaultInstalledPackagesDir() / (package + ".json"), ec);
  if (ec) {
    if (error != nullptr) {
      *error = "failed to remove installed manifest: " + ec.message();
    }
    return false;
  }

  return WriteInstalledState(records, error);
}

}  // namespace sg
