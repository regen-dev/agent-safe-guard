#include "sg/policy_state.hpp"

#include "sg/json_extract.hpp"
#include "sg/policy_catalog.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string_view>
#include <unistd.h>

namespace sg {
namespace {

struct DefaultPackageDef {
  const char* name;
  PackageMode mode;
};

constexpr DefaultPackageDef kDefaultPackages[] = {
    {"command-defense", PackageMode::kOn},
    {"output-defense", PackageMode::kOn},
    {"read-defense", PackageMode::kOn},
    {"approval-defense", PackageMode::kOn},
    {"agent-defense", PackageMode::kOn},
    {"telemetry", PackageMode::kOn},
    {"memory-defense", PackageMode::kOn},
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

PackageMode ParseMode(std::string_view raw) {
  std::string lowered = Trim(raw);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  if (lowered == "off" || lowered == "0" || lowered == "false") {
    return PackageMode::kOff;
  }
  if (lowered == "detection_only" || lowered == "detection-only" ||
      lowered == "detect" || lowered == "2") {
    return PackageMode::kDetectionOnly;
  }
  return PackageMode::kOn;
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

std::string DefaultPackagesJson() {
  std::ostringstream out;
  out << "{\"version\":1,\"packages\":[";
  for (std::size_t i = 0; i < std::size(kDefaultPackages); ++i) {
    if (i > 0) {
      out << ',';
    }
    out << "{\"package\":\"" << JsonEscape(kDefaultPackages[i].name)
        << "\",\"mode\":\"" << ToString(kDefaultPackages[i].mode)
        << "\",\"rules\":[]}";
  }
  out << "]}\n";
  return out.str();
}

}  // namespace

std::filesystem::path DefaultPolicyDir() {
  if (const char* explicit_path = std::getenv("SG_POLICY_DIR");
      explicit_path != nullptr && *explicit_path != '\0') {
    return explicit_path;
  }
  if (const char* home = std::getenv("HOME");
      home != nullptr && *home != '\0') {
    return std::filesystem::path(home) / ".claude/.safeguard/policy";
  }
  return ".claude/.safeguard/policy";
}

std::filesystem::path DefaultPackagesStatePath() {
  return DefaultPolicyDir() / "packages.json";
}

void EnsurePolicyStateScaffold() {
  std::error_code ec;
  std::filesystem::create_directories(DefaultPolicyDir(), ec);
  EnsureCatalogStateScaffold();
  if (std::filesystem::exists(DefaultPackagesStatePath(), ec) && !ec) {
    return;
  }
  std::string ignored_error;
  (void)AtomicWrite(DefaultPackagesStatePath(), DefaultPackagesJson(),
                    &ignored_error);
}

std::vector<PackagePolicyState> LoadPackagePolicyState() {
  EnsurePolicyStateScaffold();

  std::vector<PackagePolicyState> states;
  const std::string raw = ReadFile(DefaultPackagesStatePath());
  const auto array = FindJsonRaw(raw, "packages");
  if (!array.has_value()) {
    return states;
  }

  for (const auto& obj : SplitJsonObjectArray(*array)) {
    PackagePolicyState state;
    state.package = FindJsonString(obj, "package").value_or("");
    state.mode = ParseMode(FindJsonString(obj, "mode").value_or("on"));

    const auto rules_array = FindJsonRaw(obj, "rules");
    if (rules_array.has_value()) {
      for (const auto& rule_obj : SplitJsonObjectArray(*rules_array)) {
        const int rule_id = static_cast<int>(RawLongOr(rule_obj, "rule_id", 0));
        if (rule_id == 0) {
          continue;
        }
        RuleModeOverride rule;
        rule.rule_id = rule_id;
        rule.mode = ParseMode(FindJsonString(rule_obj, "mode").value_or("on"));
        state.rules.push_back(rule);
      }
    }

    if (!state.package.empty()) {
      states.push_back(std::move(state));
    }
  }

  if (states.empty()) {
    for (const auto& def : kDefaultPackages) {
      PackagePolicyState state;
      state.package = def.name;
      state.mode = def.mode;
      states.push_back(std::move(state));
    }
  }
  return states;
}

bool SavePackagePolicyState(const std::vector<PackagePolicyState>& states,
                           std::string* error) {
  std::vector<PackagePolicyState> sorted = states;
  std::sort(sorted.begin(), sorted.end(),
            [](const PackagePolicyState& lhs, const PackagePolicyState& rhs) {
              return lhs.package < rhs.package;
            });

  std::ostringstream out;
  out << "{\"version\":1,\"packages\":[";
  for (std::size_t i = 0; i < sorted.size(); ++i) {
    const auto& state = sorted[i];
    if (i > 0) {
      out << ',';
    }
    out << "{\"package\":\"" << JsonEscape(state.package) << "\",\"mode\":\""
        << ToString(state.mode) << "\",\"rules\":[";

    std::vector<RuleModeOverride> rules = state.rules;
    std::sort(rules.begin(), rules.end(),
              [](const RuleModeOverride& lhs, const RuleModeOverride& rhs) {
                return lhs.rule_id < rhs.rule_id;
              });
    for (std::size_t rule_i = 0; rule_i < rules.size(); ++rule_i) {
      if (rule_i > 0) {
        out << ',';
      }
      out << "{\"rule_id\":" << rules[rule_i].rule_id << ",\"mode\":\""
          << ToString(rules[rule_i].mode) << "\"}";
    }
    out << "]}";
  }
  out << "]}\n";

  return AtomicWrite(DefaultPackagesStatePath(), out.str(), error);
}

std::optional<PackageMode> FindPackageModeOverride(
    const std::vector<PackagePolicyState>& states, std::string_view package_name) {
  for (const auto& state : states) {
    if (state.package == package_name) {
      return state.mode;
    }
  }
  return std::nullopt;
}

std::optional<PackageMode> FindRuleModeOverride(
    const std::vector<PackagePolicyState>& states, std::string_view package_name,
    int rule_id) {
  for (const auto& state : states) {
    if (state.package != package_name) {
      continue;
    }
    for (const auto& rule : state.rules) {
      if (rule.rule_id == rule_id) {
        return rule.mode;
      }
    }
  }
  return std::nullopt;
}

}  // namespace sg
