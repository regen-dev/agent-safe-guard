#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_catalog.hpp"
#include "sg/policy_post_tool_use.hpp"
#include "sg/policy_pre_compact.hpp"
#include "sg/policy_permission_request.hpp"
#include "sg/policy_pre_tool_use.hpp"
#include "sg/policy_read_compress.hpp"
#include "sg/policy_read_guard.hpp"
#include "sg/policy_secrets.hpp"
#include "sg/policy_session_end.hpp"
#include "sg/policy_session_start.hpp"
#include "sg/policy_state.hpp"
#include "sg/policy_stats.hpp"
#include "sg/policy_stop.hpp"
#include "sg/policy_subagent_start.hpp"
#include "sg/policy_subagent_stop.hpp"
#include "sg/policy_tool_error.hpp"
#include "sg/rule_types.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/ioctl.h>
#include <termios.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <unistd.h>

namespace {

struct Feature {
  std::string env_key;
  std::string hook_name;
  std::string title;
  std::string summary;
  std::string enabled_effect;
  std::string disabled_effect;
  std::string category;
  bool enabled = true;
};

struct PackageInfo {
  std::string package;
  std::string title;
  std::string summary;
  std::string category;
};

struct RuleRow {
  sg::RuleMetadata meta;
  bool has_override = false;
  sg::PackageMode override_mode = sg::PackageMode::kOn;
  sg::PackageMode effective_mode = sg::PackageMode::kOn;
  bool has_stats = false;
  sg::RuleStatsSnapshot stats;
};

struct PackageRow {
  PackageInfo info;
  sg::PackageMode mode = sg::PackageMode::kOn;
  bool has_stats = false;
  sg::PackageStatsSnapshot stats;
  std::vector<RuleRow> rules;
};

struct CatalogData {
  std::vector<PackageInfo> packages;
  std::vector<sg::RuleMetadata> rules;
};

struct CatalogSearchMatch {
  sg::CatalogPackageRecord package;
  std::vector<sg::RuleMetadata> matching_rules;
};

enum class ConsoleView {
  kRules,
  kCatalog,
  kSettings,
};

enum class RulesPane {
  kPackages,
  kRules,
};

struct RulesUiState {
  std::size_t package_cursor = 0;
  std::size_t rule_cursor = 0;
  RulesPane active_pane = RulesPane::kPackages;
};

struct CatalogPackageRow {
  sg::CatalogPackageRecord package;
  bool installed = false;
  std::string installed_version;
  std::string installed_source;
};

enum class CatalogPane {
  kSources,
  kPackages,
  kRules,
};

struct CatalogUiState {
  std::size_t source_cursor = 0;
  std::size_t package_cursor = 0;
  std::size_t rule_cursor = 0;
  CatalogPane active_pane = CatalogPane::kSources;
};

const std::vector<Feature> kDefaultFeatures = {
    {"SG_FEATURE_PRE_TOOL_USE",
     "PreToolUse",
     "Command Firewall",
     "Stops risky Bash commands before Claude can run them.",
     "Blocks destructive commands, shell RCE patterns, unsafe verbosity, and budget-breaking actions before execution.",
     "Claude can send Bash commands without this pre-execution barrier.",
     "Command Defense",
     true},
    {"SG_FEATURE_POST_TOOL_USE",
     "PostToolUse",
     "Output Sanitizer",
     "Cleans and shrinks tool output before it goes back into context.",
     "Truncates giant outputs, strips noisy reminders, removes git hints, and logs runtime metrics.",
     "Raw tool output goes straight back into context, even when it is huge or noisy.",
     "Output Defense",
     true},
    {"SG_FEATURE_READ_GUARD",
     "ReadGuard",
     "Read Shield",
     "Blocks reads of generated, bundled, binary, or oversized files.",
     "Stops Claude from pulling in lockfiles, bundles, binaries, and oversized artifacts through Read.",
     "Claude can read bulky or generated files directly, which increases context waste and false analysis.",
     "Read Defense",
     true},
    {"SG_FEATURE_READ_COMPRESS",
     "ReadCompress",
     "Read Compressor",
     "Turns large source reads into compact structural summaries.",
     "Large files come back as imports, signatures, and structure instead of full raw content.",
     "Claude receives the full large file content and can burn context on low-signal lines.",
     "Read Defense",
     true},
    {"SG_FEATURE_PERMISSION_REQUEST",
     "PermissionRequest",
     "Permission Gate",
     "Auto-decides obvious permission prompts before they become bad approvals.",
     "Auto-denies destructive approvals and auto-allows clearly safe ones.",
     "Every permission request is left to Claude and the operator without this extra policy gate.",
     "Approval Defense",
     true},
    {"SG_FEATURE_SESSION_START",
     "SessionStart",
     "Session Tracker",
     "Starts budget and state tracking as soon as a Claude session begins.",
     "Creates the files that power budgets, telemetry, and later session summaries.",
     "Later controls lose part of their session context because no start snapshot is created.",
     "Telemetry",
     true},
    {"SG_FEATURE_SESSION_END",
     "SessionEnd",
     "Session Cleanup",
     "Closes the session cleanly and clears stale safety state.",
     "Finalizes session accounting and removes stale tracking data when the session ends.",
     "Old session state can linger and make later debugging or cleanup less reliable.",
     "Telemetry",
     true},
    {"SG_FEATURE_SUBAGENT_START",
     "SubagentStart",
     "Subagent Budget Gate",
     "Puts guardrails on spawned subagents before they start running.",
     "Checks subagent budgets, refuses unsafe launches, and injects extra guidance into the new agent.",
     "Subagents start without this budget gate and can fan out with fewer controls.",
     "Agent Defense",
     true},
    {"SG_FEATURE_SUBAGENT_STOP",
     "SubagentStop",
     "Subagent Reclaimer",
     "Returns budget and records metrics when a subagent finishes.",
     "Reclaims subagent budget and logs duration and completion state.",
     "Finished subagents leave weaker accounting behind and reclaim less state cleanly.",
     "Agent Defense",
     true},
    {"SG_FEATURE_STOP",
     "Stop",
     "Stop Summary",
     "Shows an end-of-run summary for the current Claude session.",
     "Emits stop metrics such as duration and block counts for operator visibility.",
     "You lose the final summary checkpoint at the end of the run.",
     "Telemetry",
     true},
    {"SG_FEATURE_PRE_COMPACT",
     "PreCompact",
     "Compact Memory Guard",
     "Injects current guard state before Claude compacts context.",
     "Adds safety state and session memory before compaction so Claude keeps the right context.",
     "Compaction happens without this extra state injection.",
     "Memory Defense",
     true},
    {"SG_FEATURE_TOOL_ERROR",
     "ToolError",
     "Error Telemetry",
     "Captures hook and tool failures with debug hints for later investigation.",
     "Logs tool failures and writes recovery hints into the event trail.",
     "Failures are less observable and false-positive debugging gets weaker.",
     "Telemetry",
     true},
    {"SG_FEATURE_STATUSLINE",
     "StatusLine",
     "Live Status Bar",
     "Shows cost, context, cache, clears, and budgets while Claude is running.",
     "Renders the live operator HUD in the terminal.",
     "You still have the protections, but you lose the live status HUD.",
     "Operator HUD",
     false},
    {"SG_FEATURE_REPOMAP",
     "Repomap",
     "Repo Map Primer",
     "Ships a ranked tree-sitter repo map as SessionStart context.",
     "At session start, injects a compact `path:line kind name` map of the top-ranked TS/JS files so Claude stops re-reading files to learn the layout.",
     "No repo-map primer — Claude has to rediscover structure by re-opening files every session.",
     "Operator HUD",
     true},
};

const std::vector<PackageInfo> kKnownPackages = {
    {"command-defense",
     "Command Defense",
     "Pre-execution guards for Bash, write/edit size, glob scope, and shell abuse.",
     "Core Runtime"},
    {"output-defense",
     "Output Defense",
     "Post-tool-use output cleanup, truncation, and operator-facing response shaping.",
     "Core Runtime"},
    {"read-defense",
     "Read Defense",
     "Blocks bundled, generated, or oversized reads before they waste context, and compacts large file reads into structural summaries.",
     "Core Runtime"},
    {"approval-defense",
     "Approval Defense",
     "Rule-based auto-decisions for obvious permission prompts.",
     "Core Runtime"},
    {"agent-defense",
     "Agent Defense",
     "Guards subagent launches, budgets, lifecycle accounting, and shell behavior inside spawned agents.",
     "Core Runtime"},
    {"telemetry",
     "Telemetry",
     "Session lifecycle, stop summaries, and error audit hooks exposed as package/rule state.",
     "Core Runtime"},
    {"memory-defense",
     "Memory Defense",
     "Pre-compaction context injection and session memory continuity.",
     "Core Runtime"},
    {"secrets-defense",
     "Secrets Defense",
     "Blocks credential file reads and masks .env values, showing keys with partial prefixes only.",
     "Core Runtime"},
};

constexpr std::string_view kReset = "\x1b[0m";
constexpr std::string_view kHideCursor = "\x1b[?25l";
constexpr std::string_view kShowCursor = "\x1b[?25h";
constexpr std::string_view kHeaderStyle = "\x1b[1;38;2;245;248;255;48;2;31;61;130m";
constexpr std::string_view kSubHeaderStyle = "\x1b[38;2;167;193;255m";
constexpr std::string_view kListOnStyle = "\x1b[38;2;158;255;202m";
constexpr std::string_view kListDetectStyle = "\x1b[38;2;255;221;142m";
constexpr std::string_view kListOffStyle = "\x1b[38;2;144;156;183m";
constexpr std::string_view kListCritStyle = "\x1b[38;2;255;120;120m";
constexpr std::string_view kListHighStyle = "\x1b[38;2;255;190;100m";
constexpr std::string_view kSelectedStyle = "\x1b[1;38;2;255;255;255;48;2;57;105;214m";
constexpr std::string_view kSelectedDimStyle =
    "\x1b[1;38;2;234;240;252;48;2;30;47;92m";
constexpr std::string_view kPanelStyle = "\x1b[38;2;228;235;247;48;2;15;24;56m";
constexpr std::string_view kPanelDimStyle = "\x1b[38;2;146;163;199;48;2;15;24;56m";
constexpr std::string_view kPanelSectionStyle =
    "\x1b[1;38;2;120;221;255;48;2;18;30;70m";
constexpr std::string_view kStatusOnStyle =
    "\x1b[1;38;2;14;32;19;48;2;127;255;182m";
constexpr std::string_view kStatusDetectStyle =
    "\x1b[1;38;2;51;29;0;48;2;255;221;142m";
constexpr std::string_view kStatusOffStyle =
    "\x1b[1;38;2;49;27;7;48;2;255;196;110m";
constexpr std::string_view kDividerStyle = "\x1b[38;2;67;98;173m";
constexpr std::string_view kFooterStyle = "\x1b[38;2;176;191;222m";
constexpr std::string_view kFooterErrorStyle = "\x1b[1;38;2;255;144;166m";
constexpr std::string_view kTabActiveStyle =
    "\x1b[1;38;2;255;255;255;48;2;57;105;214m";
constexpr std::string_view kTabInactiveStyle =
    "\x1b[38;2;146;163;199m";
constexpr std::string_view kTabSepStyle = "\x1b[38;2;67;98;173m";

std::string Trim(const std::string& input) {
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
  return input.substr(first, last - first);
}

struct TerminalSize {
  std::size_t cols = 100;
  std::size_t rows = 32;
};

TerminalSize GetTerminalSize() {
  winsize ws {};
  if (::ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
    return {static_cast<std::size_t>(ws.ws_col),
            static_cast<std::size_t>(ws.ws_row > 0 ? ws.ws_row : 32)};
  }
  return {};
}

std::string Repeat(char ch, std::size_t count) { return std::string(count, ch); }

std::string FitText(std::string_view text, std::size_t width) {
  if (width == 0) {
    return "";
  }
  if (text.size() <= width) {
    return std::string(text);
  }
  if (width <= 3) {
    return Repeat('.', width);
  }
  return std::string(text.substr(0, width - 3)) + "...";
}

std::string PadRight(std::string_view text, std::size_t width) {
  const std::string fitted = FitText(text, width);
  if (fitted.size() >= width) {
    return fitted;
  }
  return fitted + Repeat(' ', width - fitted.size());
}

std::vector<std::string> WrapText(std::string_view text, std::size_t width) {
  if (width == 0) {
    return {""};
  }

  std::vector<std::string> lines;
  std::size_t start = 0;
  while (start < text.size()) {
    while (start < text.size() &&
           std::isspace(static_cast<unsigned char>(text[start])) != 0 &&
           text[start] != '\n') {
      ++start;
    }
    if (start >= text.size()) {
      break;
    }
    if (text[start] == '\n') {
      lines.emplace_back("");
      ++start;
      continue;
    }

    std::size_t end = std::min(start + width, text.size());
    if (end < text.size() && text[end] != '\n' &&
        std::isspace(static_cast<unsigned char>(text[end])) == 0) {
      std::size_t split = end;
      while (split > start &&
             std::isspace(static_cast<unsigned char>(text[split - 1])) == 0) {
        --split;
      }
      if (split > start) {
        end = split;
      }
    }

    std::string line(text.substr(start, end - start));
    while (!line.empty() &&
           std::isspace(static_cast<unsigned char>(line.back())) != 0) {
      line.pop_back();
    }
    lines.push_back(line);

    start = end;
    while (start < text.size() &&
           std::isspace(static_cast<unsigned char>(text[start])) != 0) {
      if (text[start] == '\n') {
        ++start;
        break;
      }
      ++start;
    }
  }

  if (lines.empty()) {
    lines.emplace_back("");
  }
  return lines;
}

std::string Paint(std::string_view style, std::string_view content) {
  return std::string(style) + std::string(content) + std::string(kReset);
}

std::string PaintLine(std::string_view style, std::string_view content,
                      std::size_t width) {
  return Paint(style, PadRight(content, width));
}

std::string HumanizeIdentifier(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  bool capitalize = true;
  for (const unsigned char ch : input) {
    if (ch == '_' || ch == '-' || ch == '/') {
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

std::string Lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });
  return value;
}

std::optional<bool> ParseBool(std::string value) {
  value = Lower(Trim(value));
  if (value == "1" || value == "true" || value == "on" || value == "yes") {
    return true;
  }
  if (value == "0" || value == "false" || value == "off" || value == "no") {
    return false;
  }
  return std::nullopt;
}

std::optional<sg::PackageMode> ParsePackageMode(std::string value) {
  value = Lower(Trim(value));
  if (value == "1" || value == "true" || value == "on" || value == "enable" ||
      value == "enabled") {
    return sg::PackageMode::kOn;
  }
  if (value == "0" || value == "false" || value == "off" || value == "disable" ||
      value == "disabled") {
    return sg::PackageMode::kOff;
  }
  if (value == "detection_only" || value == "detection-only" ||
      value == "detect" || value == "2") {
    return sg::PackageMode::kDetectionOnly;
  }
  return std::nullopt;
}

std::string JoinStrings(const std::vector<std::string>& values,
                        std::string_view delimiter) {
  if (values.empty()) {
    return "";
  }
  std::ostringstream out;
  for (std::size_t i = 0; i < values.size(); ++i) {
    if (i > 0) {
      out << delimiter;
    }
    out << values[i];
  }
  return out.str();
}

std::string DefaultFeaturesPath() {
  const char* env = std::getenv("SG_FEATURES_FILE");
  if (env != nullptr && *env != '\0') {
    return env;
  }
  const char* home = std::getenv("HOME");
  if (home == nullptr || *home == '\0') {
    return ".claude/.safeguard/features.env";
  }
  return std::string(home) + "/.claude/.safeguard/features.env";
}

void LoadFeatures(const std::string& path, std::vector<Feature>* features) {
  if (features == nullptr) {
    return;
  }

  std::ifstream in(path);
  if (!in) {
    return;
  }

  std::unordered_map<std::string, bool> values;
  for (std::string line; std::getline(in, line);) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    const auto eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string key = Trim(line.substr(0, eq));
    const auto parsed = ParseBool(line.substr(eq + 1));
    if (parsed.has_value()) {
      values[key] = *parsed;
    }
  }

  for (auto& feature : *features) {
    const auto it = values.find(feature.env_key);
    if (it != values.end()) {
      feature.enabled = it->second;
    }
  }
}

bool SaveFeatures(const std::string& path, const std::vector<Feature>& features,
                  std::string* error) {
  std::error_code ec;
  std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
  if (ec) {
    if (error != nullptr) {
      *error = "create_directories failed: " + ec.message();
    }
    return false;
  }

  std::unordered_map<std::string, std::string> desired;
  for (const auto& feature : features) {
    desired[feature.env_key] = feature.enabled ? "1" : "0";
  }

  std::vector<std::string> lines;
  {
    std::ifstream in(path);
    for (std::string line; std::getline(in, line);) {
      lines.push_back(line);
    }
  }

  if (lines.empty()) {
    lines.push_back("# agent-safe-guard feature toggles");
    lines.push_back("# 1=enabled, 0=disabled");
  }

  std::unordered_map<std::string, bool> seen;
  for (auto& line : lines) {
    std::string working = line;
    const auto comment = working.find('#');
    if (comment != std::string::npos) {
      working = working.substr(0, comment);
    }
    const auto eq = working.find('=');
    if (eq == std::string::npos) {
      continue;
    }

    const std::string key = Trim(working.substr(0, eq));
    const auto desired_it = desired.find(key);
    if (desired_it == desired.end()) {
      continue;
    }

    line = key + "=" + desired_it->second;
    seen[key] = true;
  }

  for (const auto& feature : features) {
    if (seen[feature.env_key]) {
      continue;
    }
    lines.push_back(feature.env_key + std::string("=") +
                    (feature.enabled ? "1" : "0"));
  }

  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    if (error != nullptr) {
      *error = "open failed: " + path;
    }
    return false;
  }

  for (const auto& line : lines) {
    out << line << "\n";
  }
  return static_cast<bool>(out);
}

int FindFeature(const std::vector<Feature>& features, std::string key) {
  const std::string raw = key;
  std::transform(key.begin(), key.end(), key.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  std::replace(key.begin(), key.end(), '-', '_');

  for (std::size_t i = 0; i < features.size(); ++i) {
    std::string env = features[i].env_key;
    std::transform(env.begin(), env.end(), env.begin(),
                   [](unsigned char c) {
                     return static_cast<char>(std::tolower(c));
                   });
    if (env == key) {
      return static_cast<int>(i);
    }
    std::string short_key = env;
    constexpr std::string_view prefix = "sg_feature_";
    if (short_key.rfind(prefix.data(), 0) == 0) {
      short_key = short_key.substr(prefix.size());
      if (short_key == key) {
        return static_cast<int>(i);
      }
    }
  }

  if (raw.rfind("SG_FEATURE_", 0) == 0) {
    for (std::size_t i = 0; i < features.size(); ++i) {
      if (features[i].env_key == raw) {
        return static_cast<int>(i);
      }
    }
  }

  return -1;
}

void PrintFeatures(const std::string& path, const std::vector<Feature>& features) {
  std::cout << "asg-cli features file: " << path << "\n";
  for (const auto& feature : features) {
    std::cout << (feature.enabled ? "[x] " : "[ ] ") << feature.title << " ["
              << feature.hook_name << "] (" << feature.env_key << ")\n";
  }
}

std::string FormatTimestamp(long unix_ts) {
  if (unix_ts <= 0) {
    return "never";
  }

  const std::time_t timestamp = static_cast<std::time_t>(unix_ts);
  std::tm local_tm {};
  if (::localtime_r(&timestamp, &local_tm) == nullptr) {
    return "invalid";
  }

  char buffer[32] = {0};
  if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_tm) == 0) {
    return "invalid";
  }
  return buffer;
}

std::string ExplicitModeToken(sg::PackageMode mode) {
  switch (mode) {
    case sg::PackageMode::kDetectionOnly:
      return "DET ";
    case sg::PackageMode::kOff:
      return "OFF ";
    case sg::PackageMode::kOn:
    default:
      return "ON  ";
  }
}

std::string RuleModeToken(const RuleRow& rule) {
  if (rule.has_override) {
    return ExplicitModeToken(rule.override_mode);
  }
  switch (rule.effective_mode) {
    case sg::PackageMode::kDetectionOnly:
      return "=DET";
    case sg::PackageMode::kOff:
      return "=OFF";
    case sg::PackageMode::kOn:
    default:
      return "=ON ";
  }
}

std::string LongModeLabel(sg::PackageMode mode) {
  switch (mode) {
    case sg::PackageMode::kDetectionOnly:
      return "Detection Only";
    case sg::PackageMode::kOff:
      return "Off";
    case sg::PackageMode::kOn:
    default:
      return "On";
  }
}

std::string_view ModeLineStyle(sg::PackageMode mode) {
  switch (mode) {
    case sg::PackageMode::kDetectionOnly:
      return kListDetectStyle;
    case sg::PackageMode::kOff:
      return kListOffStyle;
    case sg::PackageMode::kOn:
    default:
      return kListOnStyle;
  }
}

std::string_view ModeStatusStyle(sg::PackageMode mode) {
  switch (mode) {
    case sg::PackageMode::kDetectionOnly:
      return kStatusDetectStyle;
    case sg::PackageMode::kOff:
      return kStatusOffStyle;
    case sg::PackageMode::kOn:
    default:
      return kStatusOnStyle;
  }
}

std::size_t PackageOrder(std::string_view package) {
  for (std::size_t i = 0; i < kKnownPackages.size(); ++i) {
    if (kKnownPackages[i].package == package) {
      return i;
    }
  }
  return kKnownPackages.size();
}

PackageInfo LookupFallbackPackageInfo(std::string_view package) {
  for (const auto& known : kKnownPackages) {
    if (known.package == package) {
      return known;
    }
  }

  PackageInfo fallback;
  fallback.package = std::string(package);
  fallback.title = HumanizeIdentifier(package);
  fallback.summary = "Package is present in local policy state or stats, but it is not registered in the built-in console catalog yet.";
  fallback.category = "External";
  return fallback;
}

std::vector<sg::RuleMetadata> LoadFallbackCatalogRules() {
  std::vector<sg::RuleMetadata> rules;
  std::set<int> seen_ids;

  const auto append_rules = [&](std::vector<sg::RuleMetadata> batch) {
    for (auto& rule : batch) {
      if (seen_ids.insert(rule.rule_id).second) {
        rules.push_back(std::move(rule));
      }
    }
  };

  append_rules(sg::ListPreToolUseRules());
  append_rules(sg::ListPostToolUseRules());
  append_rules(sg::ListPermissionRequestRules());
  append_rules(sg::ListReadCompressRules());
  append_rules(sg::ListReadGuardRules());
  append_rules(sg::ListSecretsRules());
  append_rules(sg::ListStopRules());
  append_rules(sg::ListSessionStartRules());
  append_rules(sg::ListSessionEndRules());
  append_rules(sg::ListPreCompactRules());
  append_rules(sg::ListSubagentStartRules());
  append_rules(sg::ListSubagentStopRules());
  append_rules(sg::ListToolErrorRules());

  std::sort(rules.begin(), rules.end(),
            [](const sg::RuleMetadata& lhs, const sg::RuleMetadata& rhs) {
              const std::size_t lhs_package = PackageOrder(lhs.package);
              const std::size_t rhs_package = PackageOrder(rhs.package);
              if (lhs_package != rhs_package) {
                return lhs_package < rhs_package;
              }
              if (lhs.package != rhs.package) {
                return lhs.package < rhs.package;
              }
              return lhs.rule_id < rhs.rule_id;
            });
  return rules;
}

CatalogData LoadCatalogData() {
  CatalogData data;
  std::map<std::string, PackageInfo> packages_by_name;
  std::map<int, sg::RuleMetadata> rules_by_id;

  for (const auto& package : kKnownPackages) {
    packages_by_name[package.package] = package;
  }
  for (const auto& rule : LoadFallbackCatalogRules()) {
    rules_by_id[rule.rule_id] = rule;
  }

  const auto external_packages = sg::LoadExternalPackageCatalog();
  for (const auto& package : external_packages) {
    packages_by_name[package.package] =
        {package.package, package.title, package.summary, package.category};
    for (const auto& rule : package.rules) {
      rules_by_id[rule.rule_id] = rule;
    }
  }

  for (const auto& [_, package] : packages_by_name) {
    data.packages.push_back(package);
  }
  for (const auto& [_, rule] : rules_by_id) {
    data.rules.push_back(rule);
  }

  std::sort(data.packages.begin(), data.packages.end(),
            [](const PackageInfo& lhs, const PackageInfo& rhs) {
              const std::size_t lhs_order = PackageOrder(lhs.package);
              const std::size_t rhs_order = PackageOrder(rhs.package);
              if (lhs_order != rhs_order) {
                return lhs_order < rhs_order;
              }
              return lhs.package < rhs.package;
            });
  std::sort(data.rules.begin(), data.rules.end(),
            [](const sg::RuleMetadata& lhs, const sg::RuleMetadata& rhs) {
              const std::size_t lhs_package = PackageOrder(lhs.package);
              const std::size_t rhs_package = PackageOrder(rhs.package);
              if (lhs_package != rhs_package) {
                return lhs_package < rhs_package;
              }
              if (lhs.package != rhs.package) {
                return lhs.package < rhs.package;
              }
              return lhs.rule_id < rhs.rule_id;
            });
  return data;
}

sg::PackagePolicyState* EnsurePackageState(
    std::vector<sg::PackagePolicyState>* states, std::string_view package_name) {
  if (states == nullptr) {
    return nullptr;
  }
  for (auto& state : *states) {
    if (state.package == package_name) {
      return &state;
    }
  }

  states->push_back({});
  states->back().package = std::string(package_name);
  states->back().mode = sg::PackageMode::kOn;
  return &states->back();
}

void SetPackageMode(std::vector<sg::PackagePolicyState>* states,
                    std::string_view package_name, sg::PackageMode mode) {
  sg::PackagePolicyState* state = EnsurePackageState(states, package_name);
  if (state != nullptr) {
    state->mode = mode;
  }
}

void SetRuleOverride(std::vector<sg::PackagePolicyState>* states,
                     std::string_view package_name, int rule_id,
                     std::optional<sg::PackageMode> mode) {
  sg::PackagePolicyState* state = EnsurePackageState(states, package_name);
  if (state == nullptr) {
    return;
  }

  auto it = std::find_if(state->rules.begin(), state->rules.end(),
                         [rule_id](const sg::RuleModeOverride& rule) {
                           return rule.rule_id == rule_id;
                         });

  if (!mode.has_value()) {
    if (it != state->rules.end()) {
      state->rules.erase(it);
    }
    return;
  }

  if (it == state->rules.end()) {
    state->rules.push_back({rule_id, *mode});
    return;
  }
  it->mode = *mode;
}

sg::PackageMode NextPackageMode(sg::PackageMode mode) {
  switch (mode) {
    case sg::PackageMode::kOn:
      return sg::PackageMode::kDetectionOnly;
    case sg::PackageMode::kDetectionOnly:
      return sg::PackageMode::kOff;
    case sg::PackageMode::kOff:
    default:
      return sg::PackageMode::kOn;
  }
}

std::optional<sg::PackageMode> NextRuleOverride(const PackageRow& package,
                                                const RuleRow& rule) {
  if (!rule.has_override) {
    switch (package.mode) {
      case sg::PackageMode::kOn:
        return sg::PackageMode::kDetectionOnly;
      case sg::PackageMode::kDetectionOnly:
        return sg::PackageMode::kOff;
      case sg::PackageMode::kOff:
      default:
        return sg::PackageMode::kOn;
    }
  }

  switch (rule.override_mode) {
    case sg::PackageMode::kOn:
      return sg::PackageMode::kDetectionOnly;
    case sg::PackageMode::kDetectionOnly:
      return sg::PackageMode::kOff;
    case sg::PackageMode::kOff:
    default:
      return std::nullopt;
  }
}

const sg::RuleMetadata* FindCatalogRuleById(
    const std::vector<sg::RuleMetadata>& rules, int rule_id) {
  for (const auto& rule : rules) {
    if (rule.rule_id == rule_id) {
      return &rule;
    }
  }
  return nullptr;
}

std::vector<PackageRow> BuildPackageRows(
    const CatalogData& catalog,
    const std::vector<sg::PackagePolicyState>& states,
    const std::vector<sg::RuleStatsSnapshot>& rule_stats,
    const std::vector<sg::PackageStatsSnapshot>& package_stats) {
  std::unordered_map<int, sg::RuleStatsSnapshot> rule_stats_by_id;
  for (const auto& stats : rule_stats) {
    rule_stats_by_id[stats.rule_id] = stats;
  }

  std::unordered_map<std::string, sg::PackageStatsSnapshot> package_stats_by_name;
  for (const auto& stats : package_stats) {
    package_stats_by_name[stats.package] = stats;
  }

  std::unordered_map<std::string, std::vector<sg::RuleMetadata>> rules_by_package;
  std::unordered_map<std::string, PackageInfo> package_info_by_name;
  std::set<std::string> package_names;

  for (const auto& known : catalog.packages) {
    package_names.insert(known.package);
    package_info_by_name[known.package] = known;
  }
  for (const auto& state : states) {
    package_names.insert(state.package);
  }
  for (const auto& stats : package_stats) {
    package_names.insert(stats.package);
  }
  for (const auto& rule : catalog.rules) {
    package_names.insert(rule.package);
    rules_by_package[rule.package].push_back(rule);
  }

  std::vector<std::string> ordered_packages(package_names.begin(), package_names.end());
  std::sort(ordered_packages.begin(), ordered_packages.end(),
            [](const std::string& lhs, const std::string& rhs) {
              const std::size_t lhs_order = PackageOrder(lhs);
              const std::size_t rhs_order = PackageOrder(rhs);
              if (lhs_order != rhs_order) {
                return lhs_order < rhs_order;
              }
              return lhs < rhs;
            });

  std::vector<PackageRow> rows;
  for (const auto& package_name : ordered_packages) {
    PackageRow row;
    if (const auto info_it = package_info_by_name.find(package_name);
        info_it != package_info_by_name.end()) {
      row.info = info_it->second;
    } else {
      row.info = LookupFallbackPackageInfo(package_name);
    }
    row.mode =
        sg::FindPackageModeOverride(states, package_name).value_or(sg::PackageMode::kOn);

    if (const auto stats_it = package_stats_by_name.find(package_name);
        stats_it != package_stats_by_name.end()) {
      row.has_stats = true;
      row.stats = stats_it->second;
    }

    auto& rules = rules_by_package[package_name];
    std::sort(rules.begin(), rules.end(),
              [](const sg::RuleMetadata& lhs, const sg::RuleMetadata& rhs) {
                return lhs.rule_id < rhs.rule_id;
              });

    for (const auto& meta : rules) {
      RuleRow rule;
      rule.meta = meta;
      if (const auto override_mode =
              sg::FindRuleModeOverride(states, package_name, meta.rule_id);
          override_mode.has_value()) {
        rule.has_override = true;
        rule.override_mode = *override_mode;
        rule.effective_mode = *override_mode;
      } else {
        rule.effective_mode = row.mode;
      }

      if (const auto stats_it = rule_stats_by_id.find(meta.rule_id);
          stats_it != rule_stats_by_id.end()) {
        rule.has_stats = true;
        rule.stats = stats_it->second;
      }

      row.rules.push_back(std::move(rule));
    }

    rows.push_back(std::move(row));
  }

  return rows;
}

void PrintRules(const std::vector<PackageRow>& packages) {
  std::cout << "asg-cli policy dir: " << sg::DefaultPolicyDir().string() << "\n";
  for (const auto& package : packages) {
    std::cout << "[" << ExplicitModeToken(package.mode) << "] " << package.info.title
              << " (" << package.info.package << ") rules=" << package.rules.size()
              << " matched="
              << (package.has_stats ? package.stats.matched_total : 0)
              << " blocked="
              << (package.has_stats ? package.stats.blocked_total : 0)
              << " modified="
              << (package.has_stats ? package.stats.modified_total : 0)
              << " detect_only="
              << (package.has_stats ? package.stats.detect_only_total : 0) << "\n";

    for (const auto& rule : package.rules) {
      std::cout << "  [" << RuleModeToken(rule) << "] " << rule.meta.rule_id << " "
                << rule.meta.name << " phase=" << sg::ToString(rule.meta.phase)
                << " severity=" << sg::ToString(rule.meta.severity)
                << " matched=" << (rule.has_stats ? rule.stats.matched_total : 0)
                << " blocked=" << (rule.has_stats ? rule.stats.blocked_total : 0)
                << " modified=" << (rule.has_stats ? rule.stats.modified_total : 0)
                << " errors=" << (rule.has_stats ? rule.stats.error_total : 0)
                << "\n";
      if (rule.has_override) {
        std::cout << "    override=" << sg::ToString(rule.override_mode) << "\n";
      }
    }
  }
}

std::vector<CatalogPackageRow> BuildCatalogPackageRows(
    const std::vector<sg::CatalogSourceRecord>& catalogs,
    const std::vector<sg::CatalogPackageRecord>& packages,
    const std::vector<sg::InstalledPackageRecord>& installed,
    const CatalogUiState& state) {
  std::unordered_map<std::string, sg::InstalledPackageRecord> installed_by_package;
  for (const auto& record : installed) {
    installed_by_package[record.package] = record;
  }

  // Built-in compiled packages count as installed even without an
  // installed.json entry so the Catalog view reflects reality.
  std::unordered_set<std::string> builtin_packages;
  for (const auto& known : kKnownPackages) {
    builtin_packages.insert(known.package);
  }

  std::string selected_catalog_id;
  if (!catalogs.empty()) {
    const std::size_t cursor =
        std::min(state.source_cursor, catalogs.size() - 1);
    selected_catalog_id = catalogs[cursor].catalog_id;
  }

  std::vector<CatalogPackageRow> rows;
  for (const auto& package : packages) {
    if (!selected_catalog_id.empty() && package.catalog_id != selected_catalog_id) {
      continue;
    }
    // Skip catalog entries that duplicate built-in compiled packages.
    if (builtin_packages.count(package.package) > 0) {
      continue;
    }

    CatalogPackageRow row;
    row.package = package;
    if (const auto installed_it = installed_by_package.find(package.package);
        installed_it != installed_by_package.end()) {
      row.installed = true;
      row.installed_version = installed_it->second.version;
      row.installed_source = installed_it->second.source_url.empty()
                                 ? installed_it->second.source_path
                                 : installed_it->second.source_url;
    }
    rows.push_back(std::move(row));
  }

  std::sort(rows.begin(), rows.end(),
            [](const CatalogPackageRow& lhs, const CatalogPackageRow& rhs) {
              if (lhs.installed != rhs.installed) {
                return lhs.installed > rhs.installed;
              }
              if (lhs.package.title != rhs.package.title) {
                return lhs.package.title < rhs.package.title;
              }
              return lhs.package.package < rhs.package.package;
            });
  return rows;
}

bool CatalogPackageMatches(const sg::CatalogPackageRecord& package,
                           std::string_view lowered_term,
                           std::vector<sg::RuleMetadata>* matching_rules) {
  if (lowered_term.empty()) {
    return true;
  }

  const auto text_matches = [&](std::string_view value) {
    return Lower(std::string(value)).find(lowered_term) != std::string::npos;
  };

  if (text_matches(package.catalog_id) || text_matches(package.catalog_title) ||
      text_matches(package.package) || text_matches(package.title) ||
      text_matches(package.summary) || text_matches(package.version)) {
    return true;
  }
  for (const auto& tag : package.tags) {
    if (text_matches(tag)) {
      return true;
    }
  }
  for (const auto& phase : package.phases) {
    if (text_matches(phase)) {
      return true;
    }
  }
  for (const auto& rule : package.rules) {
    if (text_matches(rule.name) ||
        text_matches(std::to_string(rule.rule_id)) ||
        text_matches(sg::ToString(rule.phase)) ||
        text_matches(sg::ToString(rule.severity))) {
      if (matching_rules != nullptr) {
        matching_rules->push_back(rule);
      }
    }
  }
  return matching_rules != nullptr && !matching_rules->empty();
}

std::vector<CatalogSearchMatch> SearchCatalogPackages(
    const std::vector<sg::CatalogPackageRecord>& packages, std::string_view term) {
  std::vector<CatalogSearchMatch> matches;
  const std::string lowered_term = Lower(std::string(term));
  for (const auto& package : packages) {
    CatalogSearchMatch match;
    match.package = package;
    if (!CatalogPackageMatches(match.package, lowered_term, &match.matching_rules)) {
      continue;
    }
    matches.push_back(std::move(match));
  }
  return matches;
}

void PrintCatalogs(const std::vector<sg::CatalogSourceRecord>& catalogs,
                   const std::vector<sg::CatalogPackageRecord>& packages) {
  std::unordered_map<std::string, std::size_t> package_counts;
  for (const auto& package : packages) {
    package_counts[package.catalog_id] += 1;
  }

  std::cout << "asg-cli catalogs file: "
            << sg::DefaultCatalogsStatePath().string() << "\n";
  if (catalogs.empty()) {
    std::cout << "(no catalogs configured)\n";
    return;
  }

  for (const auto& catalog : catalogs) {
    const bool synced = catalog.last_synced_at > 0;
    const std::string display =
        catalog.display_name.empty()
            ? HumanizeIdentifier(catalog.catalog_id.empty() ? catalog.source_url
                                                            : catalog.catalog_id)
            : catalog.display_name;
    const std::string catalog_id =
        catalog.catalog_id.empty() ? "pending" : catalog.catalog_id;
    std::cout << "[" << (synced ? "SYNCED" : "ADDED ") << "] " << display
              << " (" << catalog_id << ")"
              << " packages=" << package_counts[catalog.catalog_id]
              << " last_sync=" << FormatTimestamp(catalog.last_synced_at) << "\n";
    std::cout << "  source=" << catalog.source_url << "\n";
    std::cout << "  cache=" << catalog.cache_path << "\n";
  }
}

void PrintCatalogSearchResults(const std::vector<CatalogSearchMatch>& matches,
                               std::string_view term) {
  std::cout << "asg-cli catalog search: "
            << (term.empty() ? "(all packages)" : std::string(term)) << "\n";
  if (matches.empty()) {
    std::cout << "(no catalog packages matched)\n";
    return;
  }

  for (const auto& match : matches) {
    std::cout << "[" << match.package.catalog_id << "] " << match.package.title
              << " (" << match.package.package << ")"
              << " version=" << (match.package.version.empty() ? "unknown"
                                                               : match.package.version)
              << "\n";
    if (!match.package.summary.empty()) {
      std::cout << "  " << match.package.summary << "\n";
    }
    std::cout << "  phases="
              << (match.package.phases.empty() ? "unknown"
                                               : JoinStrings(match.package.phases, ","))
              << " tags="
              << (match.package.tags.empty() ? "-" : JoinStrings(match.package.tags, ","))
              << "\n";
    std::cout << "  download=" << match.package.download_url << "\n";
    if (!match.matching_rules.empty()) {
      for (const auto& rule : match.matching_rules) {
        std::cout << "  rule " << rule.rule_id << " " << rule.name
                  << " phase=" << sg::ToString(rule.phase)
                  << " severity=" << sg::ToString(rule.severity) << "\n";
      }
    }
  }
}

std::string PaintSelectableLine(std::string_view base_style, std::string_view content,
                                std::size_t width, bool selected, bool active) {
  if (selected) {
    return PaintLine(active ? kSelectedStyle : kSelectedDimStyle, content, width);
  }
  return PaintLine(base_style, content, width);
}

std::vector<std::filesystem::path> ExpandManifestInstallPaths(
    const std::string& input, std::string* error) {
  const std::filesystem::path path(input);
  std::error_code ec;
  if (!std::filesystem::exists(path, ec) || ec) {
    if (error != nullptr) {
      *error = "path does not exist: " + input;
    }
    return {};
  }

  if (std::filesystem::is_regular_file(path, ec) && !ec) {
    if (path.extension() != ".json") {
      if (error != nullptr) {
        *error = "manifest file must end with .json: " + input;
      }
      return {};
    }
    return {path};
  }

  if (std::filesystem::is_directory(path, ec) && !ec) {
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(path, ec)) {
      if (ec) {
        break;
      }
      if (entry.is_regular_file() && entry.path().extension() == ".json") {
        files.push_back(entry.path());
      }
    }
    std::sort(files.begin(), files.end());
    if (files.empty() && error != nullptr) {
      *error = "directory has no .json manifests: " + input;
    }
    return files;
  }

  if (error != nullptr) {
    *error = "path is neither a manifest file nor a manifest directory: " + input;
  }
  return {};
}

void ClampRulesUiState(const std::vector<PackageRow>& packages,
                       RulesUiState* state) {
  if (state == nullptr || packages.empty()) {
    return;
  }
  if (state->package_cursor >= packages.size()) {
    state->package_cursor = packages.size() - 1;
  }

  const auto& selected_package = packages[state->package_cursor];
  if (selected_package.rules.empty()) {
    state->rule_cursor = 0;
    state->active_pane = RulesPane::kPackages;
    return;
  }
  if (state->rule_cursor >= selected_package.rules.size()) {
    state->rule_cursor = selected_package.rules.size() - 1;
  }
}

void ClampCatalogUiState(const std::vector<sg::CatalogSourceRecord>& catalogs,
                         const std::vector<CatalogPackageRow>& packages,
                         CatalogUiState* state) {
  if (state == nullptr) {
    return;
  }
  if (catalogs.empty()) {
    state->source_cursor = 0;
    state->package_cursor = 0;
    state->active_pane = CatalogPane::kSources;
    return;
  }
  if (state->source_cursor >= catalogs.size()) {
    state->source_cursor = catalogs.size() - 1;
  }
  if (packages.empty()) {
    state->package_cursor = 0;
    state->active_pane = CatalogPane::kSources;
    return;
  }
  if (state->package_cursor >= packages.size()) {
    state->package_cursor = packages.size() - 1;
  }
}

// Clamp a column of painted lines to max_rows.
// header_count fixed lines stay pinned at top.
// cursor is the 0-based index among items (after headers) to keep visible.
// Use cursor == SIZE_MAX for columns without a cursor (detail panes).
void ClampColumn(std::vector<std::string>& lines, std::size_t header_count,
                 std::size_t cursor, std::size_t max_rows,
                 std::size_t col_width) {
  if (lines.size() <= max_rows) {
    return;
  }
  const std::size_t pinned = std::min(header_count, max_rows);
  const std::size_t available = max_rows - pinned;
  const std::size_t item_count =
      lines.size() > header_count ? lines.size() - header_count : 0;
  if (item_count <= available) {
    lines.resize(pinned + item_count);
    return;
  }

  // Compute scroll offset to keep cursor visible.
  std::size_t offset = 0;
  if (cursor != SIZE_MAX && cursor < item_count) {
    if (cursor > available / 2) {
      offset = cursor - available / 2;
    }
    if (offset + available > item_count) {
      offset = item_count - available;
    }
  }

  std::vector<std::string> result;
  for (std::size_t i = 0; i < pinned && i < lines.size(); ++i) {
    result.push_back(std::move(lines[i]));
  }
  const bool has_above = offset > 0;
  const bool has_below = offset + available < item_count;
  const std::size_t slot_first = has_above ? 1 : 0;
  const std::size_t slot_last = has_below ? 1 : 0;
  const std::size_t content_slots = available - slot_first - slot_last;

  if (has_above) {
    result.push_back(
        PaintLine(kPanelDimStyle,
                  "  \xe2\x96\xb2 " + std::to_string(offset) + " more",
                  col_width));
  }
  for (std::size_t i = 0; i < content_slots; ++i) {
    const std::size_t src = header_count + offset + slot_first + i;
    if (src < lines.size()) {
      result.push_back(std::move(lines[src]));
    }
  }
  if (has_below) {
    const std::size_t remaining =
        item_count - (offset + slot_first + content_slots);
    result.push_back(
        PaintLine(kPanelDimStyle,
                  "  \xe2\x96\xbc " + std::to_string(remaining) + " more",
                  col_width));
  }
  lines = std::move(result);
}

std::string BuildTabBar(ConsoleView active, std::size_t total_width) {
  struct TabDef {
    ConsoleView view;
    std::string_view label;
  };
  constexpr TabDef tabs[] = {
      {ConsoleView::kRules, "Rules"},
      {ConsoleView::kCatalog, "Catalog"},
      {ConsoleView::kSettings, "Settings"},
  };
  std::string bar = " ";
  for (std::size_t i = 0; i < 3; ++i) {
    if (i > 0) {
      bar += std::string(kReset) + std::string(kTabSepStyle) + "  |  " +
             std::string(kReset);
    }
    if (tabs[i].view == active) {
      bar += std::string(kTabActiveStyle) + " " + std::string(tabs[i].label) +
             " " + std::string(kReset);
    } else {
      bar += std::string(kTabInactiveStyle) + std::string(tabs[i].label) +
             std::string(kReset);
    }
  }
  bar += std::string(kTabSepStyle) +
         std::string("   Tab to switch") + std::string(kReset);
  // Pad to total_width accounting for ANSI escape sequences
  std::size_t visible = 0;
  bool in_escape = false;
  for (char ch : bar) {
    if (ch == '\x1b') {
      in_escape = true;
    } else if (in_escape && ch == 'm') {
      in_escape = false;
    } else if (!in_escape) {
      ++visible;
    }
  }
  if (visible < total_width) {
    bar += std::string(total_width - visible, ' ');
  }
  return bar;
}

void DrawRulesUI(const std::vector<PackageRow>& packages, const RulesUiState& state,
                 bool dirty, const std::string& status_message = "",
                 bool status_is_error = false) {
  const TerminalSize term = GetTerminalSize();
  const std::size_t total_width = std::max<std::size_t>(term.cols, 88);
  std::size_t left_width = total_width >= 120 ? 28 : 24;
  std::size_t mid_width = total_width >= 120 ? 42 : 34;
  std::size_t gap_width = 3;
  std::size_t right_width =
      total_width > left_width + mid_width + gap_width * 2
          ? total_width - left_width - mid_width - gap_width * 2
          : 28;
  if (right_width < 32) {
    const std::size_t deficit = 32 - right_width;
    if (mid_width > 26 + deficit) {
      mid_width -= deficit;
    } else if (left_width > 20 + deficit) {
      left_width -= deficit;
    }
    right_width = total_width - left_width - mid_width - gap_width * 2;
  }

  const PackageRow* selected_package =
      packages.empty() ? nullptr : &packages[state.package_cursor];
  const RuleRow* selected_rule =
      (selected_package == nullptr || selected_package->rules.empty())
          ? nullptr
          : &selected_package->rules[state.rule_cursor];

  std::vector<std::string> package_lines;
  package_lines.push_back(PaintLine(kPanelSectionStyle, "PACKAGES", left_width));
  if (packages.empty()) {
    package_lines.push_back(PaintLine(kPanelDimStyle, "No packages available",
                                      left_width));
  } else {
    for (std::size_t i = 0; i < packages.size(); ++i) {
      const auto& package = packages[i];
      const bool selected = i == state.package_cursor;
      const std::string prefix = selected ? "> " : "  ";
      const std::string label = prefix + "[" + ExplicitModeToken(package.mode) +
                                "] " + package.info.title;
      package_lines.push_back(PaintSelectableLine(
          ModeLineStyle(package.mode), label, left_width, selected,
          selected && state.active_pane == RulesPane::kPackages));
    }
  }

  std::vector<std::string> rule_lines;
  rule_lines.push_back(PaintLine(kPanelSectionStyle, "RULES", mid_width));
  if (selected_package == nullptr || selected_package->rules.empty()) {
    rule_lines.push_back(PaintLine(kPanelDimStyle,
                                   "No compiled rules in this package yet",
                                   mid_width));
  } else {
    for (std::size_t i = 0; i < selected_package->rules.size(); ++i) {
      const auto& rule = selected_package->rules[i];
      const bool selected = i == state.rule_cursor;
      const std::string prefix = selected ? "> " : "  ";
      const std::string label =
          prefix + "[" + RuleModeToken(rule) + "] " +
          std::to_string(rule.meta.rule_id) + " " + rule.meta.name;
      rule_lines.push_back(PaintSelectableLine(
          ModeLineStyle(rule.effective_mode), label, mid_width, selected,
          selected && state.active_pane == RulesPane::kRules));
    }
  }

  std::vector<std::string> detail_lines;
  detail_lines.push_back(PaintLine(kPanelSectionStyle, "DETAILS", right_width));
  if (selected_package == nullptr) {
    detail_lines.push_back(PaintLine(kPanelDimStyle, "No package selected",
                                     right_width));
  } else if (selected_rule != nullptr) {
    detail_lines.push_back(PaintLine(
        ModeStatusStyle(selected_rule->effective_mode),
        " MODE  " + LongModeLabel(selected_rule->effective_mode), right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        std::to_string(selected_rule->meta.rule_id) + "  " +
            selected_rule->meta.name,
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Package: " + selected_package->info.package + "  |  Phase: " +
            std::string(sg::ToString(selected_rule->meta.phase)),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Severity: " + std::string(sg::ToString(selected_rule->meta.severity)),
        right_width));
    if (!selected_rule->meta.description.empty()) {
      detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
      for (const auto& line :
           WrapText(selected_rule->meta.description, right_width)) {
        detail_lines.push_back(PaintLine(kPanelStyle, line, right_width));
      }
    }
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "OVERRIDE", right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        selected_rule->has_override
            ? "Rule override: " + LongModeLabel(selected_rule->override_mode)
            : "Rule override: inherited from package (" +
                  LongModeLabel(selected_package->mode) + ")",
        right_width));
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "STATS", right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Matched: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.matched_total
                               : 0) +
            "  Blocked: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.blocked_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Allowed: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.allowed_total
                               : 0) +
            "  Modified: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.modified_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Suppressed: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.suppressed_total
                               : 0) +
            "  Detect: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.detect_only_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Errors: " +
            std::to_string(selected_rule->has_stats
                               ? selected_rule->stats.error_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Last disposition: " +
            std::string(selected_rule->has_stats &&
                                !selected_rule->stats.last_disposition.empty()
                            ? selected_rule->stats.last_disposition
                            : "never"),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Last matched: " +
            FormatTimestamp(selected_rule->has_stats
                                ? selected_rule->stats.last_matched_at
                                : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Last blocked: " +
            FormatTimestamp(selected_rule->has_stats
                                ? selected_rule->stats.last_blocked_at
                                : 0),
        right_width));
    if (selected_rule->has_stats && !selected_rule->stats.last_project.empty()) {
      for (const auto& line :
           WrapText("Last project: " + selected_rule->stats.last_project,
                    right_width)) {
        detail_lines.push_back(PaintLine(kPanelDimStyle, line, right_width));
      }
    }
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "PACKAGE", right_width));
    for (const auto& line : WrapText(selected_package->info.summary, right_width)) {
      detail_lines.push_back(PaintLine(kPanelStyle, line, right_width));
    }
  } else {
    detail_lines.push_back(PaintLine(
        ModeStatusStyle(selected_package->mode),
        " PACKAGE  " + LongModeLabel(selected_package->mode), right_width));
    detail_lines.push_back(
        PaintLine(kPanelStyle, selected_package->info.title, right_width));
    detail_lines.push_back(PaintLine(kPanelDimStyle,
                                     selected_package->info.package,
                                     right_width));
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "SUMMARY", right_width));
    for (const auto& line :
         WrapText(selected_package->info.summary, right_width)) {
      detail_lines.push_back(PaintLine(kPanelStyle, line, right_width));
    }
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "STATS", right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Rules: " + std::to_string(selected_package->rules.size()) +
            "  Matched: " +
            std::to_string(selected_package->has_stats
                               ? selected_package->stats.matched_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Blocked: " +
            std::to_string(selected_package->has_stats
                               ? selected_package->stats.blocked_total
                               : 0) +
            "  Modified: " +
            std::to_string(selected_package->has_stats
                               ? selected_package->stats.modified_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Allowed: " +
            std::to_string(selected_package->has_stats
                               ? selected_package->stats.allowed_total
                               : 0) +
            "  Detect: " +
            std::to_string(selected_package->has_stats
                               ? selected_package->stats.detect_only_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Errors: " +
            std::to_string(selected_package->has_stats
                               ? selected_package->stats.error_total
                               : 0),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Last matched: " +
            FormatTimestamp(selected_package->has_stats
                                ? selected_package->stats.last_matched_at
                                : 0),
        right_width));
  }

  detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  detail_lines.push_back(PaintLine(kPanelSectionStyle, "CONTROLS", right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Left/Right or h/l switch package/rule pane",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Up/Down or j/k move in active pane",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Space  Cycle package or rule mode",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "R      Reset selected rule override",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "S      Save policy state and exit",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Q      Quit without saving",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  detail_lines.push_back(PaintLine(
      dirty ? kStatusOffStyle : kPanelStyle,
      dirty ? " UNSAVED CHANGES PENDING" : " ALL CHANGES SAVED",
      right_width));

  std::cout << "\x1b[2J\x1b[H" << kHideCursor;

  const std::size_t total_rules = std::accumulate(
      packages.begin(), packages.end(), static_cast<std::size_t>(0),
      [](std::size_t acc, const PackageRow& package) {
        return acc + package.rules.size();
      });
  const std::string title = " ASG Policy Console";
  const std::string summary = " Rules  " + std::to_string(packages.size()) +
                              " packages / " + std::to_string(total_rules) +
                              " rules";
  std::string header;
  if (title.size() + summary.size() <= total_width) {
    header = title + Repeat(' ', total_width - title.size() - summary.size()) +
             summary;
  } else {
    header = FitText(title, total_width);
  }
  std::cout << Paint(kHeaderStyle, PadRight(header, total_width)) << "\n";
  std::cout << BuildTabBar(ConsoleView::kRules, total_width) << "\n\n";

  // header(1) + tabbar(1) + blank(1) + footer_blank(1) + footer(1) = 5
  const std::size_t max_body = term.rows > 5 ? term.rows - 5 : term.rows;
  ClampColumn(package_lines, 1, state.package_cursor, max_body, left_width);
  ClampColumn(rule_lines, 1, state.rule_cursor, max_body, mid_width);
  ClampColumn(detail_lines, 1, SIZE_MAX, max_body, right_width);

  const std::string gap = Paint(
      kDividerStyle,
      Repeat(' ', gap_width / 2) + "|" +
          Repeat(' ', gap_width - gap_width / 2 - 1));
  const std::size_t body_rows =
      std::max(package_lines.size(), std::max(rule_lines.size(), detail_lines.size()));
  for (std::size_t row = 0; row < body_rows; ++row) {
    const std::string left =
        row < package_lines.size() ? package_lines[row]
                                   : PaintLine(kPanelStyle, "", left_width);
    const std::string middle =
        row < rule_lines.size() ? rule_lines[row]
                                : PaintLine(kPanelStyle, "", mid_width);
    const std::string right =
        row < detail_lines.size() ? detail_lines[row]
                                  : PaintLine(kPanelStyle, "", right_width);
    std::cout << left << gap << middle << gap << right << "\n";
  }

  std::cout << "\n";
  std::cout << Paint(
                   status_is_error ? kFooterErrorStyle : kFooterStyle,
                   PadRight(status_message.empty()
                                ? "Rules home: package mode on the left, rule override in the middle, live stats on the right."
                                : status_message,
                            total_width));
  std::cout.flush();
}

void DrawCatalogUI(const std::vector<sg::CatalogSourceRecord>& catalogs,
                   const std::vector<CatalogPackageRow>& packages,
                   const CatalogUiState& state, bool dirty,
                   const std::vector<sg::PackagePolicyState>& policy_states,
                   const std::string& status_message = "",
                   bool status_is_error = false) {
  const TerminalSize term = GetTerminalSize();
  const std::size_t total_width = std::max<std::size_t>(term.cols, 94);
  std::size_t left_width = total_width >= 120 ? 28 : 24;
  std::size_t mid_width = total_width >= 120 ? 36 : 32;
  const std::size_t gap_width = 3;
  std::size_t right_width =
      total_width > left_width + mid_width + gap_width * 2
          ? total_width - left_width - mid_width - gap_width * 2
          : 32;
  if (right_width < 34) {
    const std::size_t deficit = 34 - right_width;
    if (mid_width > 24 + deficit) {
      mid_width -= deficit;
    } else if (left_width > 20 + deficit) {
      left_width -= deficit;
    }
    right_width = total_width - left_width - mid_width - gap_width * 2;
  }

  const sg::CatalogSourceRecord* selected_catalog =
      catalogs.empty() ? nullptr : &catalogs[state.source_cursor];
  const CatalogPackageRow* selected_package =
      packages.empty() ? nullptr : &packages[state.package_cursor];

  std::vector<std::string> catalog_lines;
  catalog_lines.push_back(PaintLine(kPanelSectionStyle, "CATALOGS", left_width));
  if (catalogs.empty()) {
    catalog_lines.push_back(
        PaintLine(kPanelDimStyle, "No catalog sources configured", left_width));
  } else {
    for (std::size_t i = 0; i < catalogs.size(); ++i) {
      const auto& catalog = catalogs[i];
      const bool selected = i == state.source_cursor;
      const bool synced = catalog.last_synced_at > 0;
      const std::string prefix = selected ? "> " : "  ";
      const std::string label =
          prefix + "[" + std::string(synced ? "SYNC" : "ADD ") + "] " +
          (catalog.display_name.empty() ? HumanizeIdentifier(catalog.catalog_id)
                                        : catalog.display_name);
      catalog_lines.push_back(PaintSelectableLine(
          synced ? kListOnStyle : kListDetectStyle, label, left_width, selected,
          selected && state.active_pane == CatalogPane::kSources));
    }
  }

  std::vector<std::string> package_lines;
  package_lines.push_back(PaintLine(kPanelSectionStyle, "PACKAGES", mid_width));
  if (packages.empty()) {
    package_lines.push_back(PaintLine(
        kPanelDimStyle, "No cached packages for selected catalog", mid_width));
  } else {
    for (std::size_t i = 0; i < packages.size(); ++i) {
      const auto& package = packages[i];
      const bool selected = i == state.package_cursor;
      const std::string prefix = selected ? "> " : "  ";
      const std::string label =
          prefix + "[" + std::string(package.installed ? "INST" : "AVAI") +
          "] " + package.package.title;
      package_lines.push_back(PaintSelectableLine(
          package.installed ? kListOnStyle : kPanelDimStyle, label, mid_width,
          selected, selected && state.active_pane == CatalogPane::kPackages));
    }
  }

  std::vector<std::string> detail_lines;
  std::size_t detail_rule_line = SIZE_MAX;
  detail_lines.push_back(PaintLine(kPanelSectionStyle, "DETAILS", right_width));
  if (selected_package != nullptr) {
    detail_lines.push_back(PaintLine(
        selected_package->installed ? kStatusOnStyle : kStatusDetectStyle,
        selected_package->installed ? " STATUS  INSTALLED"
                                    : " STATUS  AVAILABLE",
        right_width));
    detail_lines.push_back(
        PaintLine(kPanelStyle, selected_package->package.title, right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        selected_package->package.package + "  |  " +
            selected_package->package.catalog_id,
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Version: " +
            (selected_package->package.version.empty()
                 ? std::string("unknown")
                 : selected_package->package.version),
        right_width));
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "SUMMARY", right_width));
    for (const auto& line :
         WrapText(selected_package->package.summary, right_width)) {
      detail_lines.push_back(PaintLine(kPanelStyle, line, right_width));
    }
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "PACKAGE", right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Rules: " + std::to_string(selected_package->package.rules.size()),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Phases: " +
            (selected_package->package.phases.empty()
                 ? std::string("unknown")
                 : JoinStrings(selected_package->package.phases, ",")),
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        "Tags: " +
            (selected_package->package.tags.empty()
                 ? std::string("-")
                 : JoinStrings(selected_package->package.tags, ",")),
        right_width));
    if (selected_package->installed) {
      detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
      detail_lines.push_back(PaintLine(kPanelSectionStyle, "INSTALLED", right_width));
      detail_lines.push_back(PaintLine(
          kPanelStyle,
          "Version: " +
              (selected_package->installed_version.empty()
                   ? std::string("unknown")
                   : selected_package->installed_version),
          right_width));
      for (const auto& line :
           WrapText("Source: " + selected_package->installed_source, right_width)) {
        detail_lines.push_back(PaintLine(kPanelDimStyle, line, right_width));
      }
    }
    if (!selected_package->package.rules.empty()) {
      detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
      detail_lines.push_back(
          PaintLine(kPanelSectionStyle, "RULES", right_width));
      const std::size_t rules_section_start = detail_lines.size();
      const bool rules_focused =
          state.active_pane == CatalogPane::kRules;
      for (std::size_t i = 0; i < selected_package->package.rules.size();
           ++i) {
        const auto& rule = selected_package->package.rules[i];
        const bool sel = i == state.rule_cursor;
        if (sel) {
          detail_rule_line = detail_lines.size();
        }
        // Resolve rule mode from policy state.
        const auto override_mode = sg::FindRuleModeOverride(
            policy_states, selected_package->package.package, rule.rule_id);
        const bool rule_off =
            override_mode.has_value() &&
            *override_mode == sg::PackageMode::kOff;
        const std::string prefix = sel ? "> " : "  ";
        const std::string mode_icon = rule_off ? "[OFF] " : "[ON]  ";
        const std::string severity_tag =
            rule.severity == sg::RuleSeverity::kCritical ? "CRIT"
            : rule.severity == sg::RuleSeverity::kHigh   ? "HIGH"
                                                         : "MED ";
        const std::string label = prefix + mode_icon +
                                  std::to_string(rule.rule_id) + " " +
                                  rule.name + " [" + severity_tag + "]";
        const auto style =
            rule_off ? kListOffStyle
            : rule.severity == sg::RuleSeverity::kCritical ? kListCritStyle
            : rule.severity == sg::RuleSeverity::kHigh     ? kListHighStyle
                                                           : kPanelDimStyle;
        detail_lines.push_back(PaintSelectableLine(
            style, label, right_width, sel, sel && rules_focused));
      }
      // Show description of selected rule below the list.
      if (state.rule_cursor <
          selected_package->package.rules.size()) {
        const auto& sel_rule =
            selected_package->package.rules[state.rule_cursor];
        if (!sel_rule.description.empty()) {
          detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
          detail_lines.push_back(PaintLine(
              kPanelSectionStyle, "RULE DETAIL", right_width));
          for (const auto& line :
               WrapText(sel_rule.description, right_width)) {
            detail_lines.push_back(
                PaintLine(kPanelStyle, line, right_width));
          }
        }
      }
    }
  } else if (selected_catalog != nullptr) {
    const bool synced = selected_catalog->last_synced_at > 0;
    detail_lines.push_back(PaintLine(
        synced ? kStatusOnStyle : kStatusDetectStyle,
        synced ? " STATUS  SYNCED" : " STATUS  ADDED",
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelStyle,
        selected_catalog->display_name.empty()
            ? HumanizeIdentifier(selected_catalog->catalog_id)
            : selected_catalog->display_name,
        right_width));
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        selected_catalog->catalog_id.empty() ? "pending"
                                             : selected_catalog->catalog_id,
        right_width));
    detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
    detail_lines.push_back(PaintLine(kPanelSectionStyle, "SOURCE", right_width));
    for (const auto& line :
         WrapText(selected_catalog->source_url, right_width)) {
      detail_lines.push_back(PaintLine(kPanelStyle, line, right_width));
    }
    for (const auto& line :
         WrapText("Cache: " + selected_catalog->cache_path, right_width)) {
      detail_lines.push_back(PaintLine(kPanelDimStyle, line, right_width));
    }
    detail_lines.push_back(PaintLine(
        kPanelDimStyle,
        "Last sync: " + FormatTimestamp(selected_catalog->last_synced_at),
        right_width));
  } else {
    detail_lines.push_back(
        PaintLine(kPanelDimStyle, "No catalog selected", right_width));
  }

  detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  detail_lines.push_back(PaintLine(kPanelSectionStyle, "CONTROLS", right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Left/Right or h/l switch source/package pane",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Up/Down or j/k move in active pane",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Enter  Sync catalog / install package",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Y      Sync all catalogs now",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "I      Install or update selected package",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "X      Remove selected installed package",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "S      Save rules/settings changes and exit",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelDimStyle,
                                   "Q      Quit without saving",
                                   right_width));
  detail_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  detail_lines.push_back(PaintLine(
      dirty ? kStatusOffStyle : kPanelStyle,
      dirty ? " CATALOG ACTIONS APPLY IMMEDIATELY  |  RULES/SETTINGS UNSAVED"
            : " CATALOG ACTIONS APPLY IMMEDIATELY",
      right_width));

  std::cout << "\x1b[2J\x1b[H" << kHideCursor;

  const std::string title = " ASG Policy Console";
  const std::string summary = " Catalog  " + std::to_string(catalogs.size()) +
                              " sources / " + std::to_string(packages.size()) +
                              " visible packages";
  std::string header;
  if (title.size() + summary.size() <= total_width) {
    header = title + Repeat(' ', total_width - title.size() - summary.size()) +
             summary;
  } else {
    header = FitText(title, total_width);
  }
  std::cout << Paint(kHeaderStyle, PadRight(header, total_width)) << "\n";
  std::cout << BuildTabBar(ConsoleView::kCatalog, total_width) << "\n\n";

  const std::size_t max_body = term.rows > 5 ? term.rows - 5 : term.rows;
  ClampColumn(catalog_lines, 1, state.source_cursor, max_body, left_width);
  ClampColumn(package_lines, 1, state.package_cursor, max_body, mid_width);
  // When navigating rules, scroll detail pane to keep selected rule visible.
  const std::size_t detail_focus =
      (state.active_pane == CatalogPane::kRules && detail_rule_line != SIZE_MAX)
          ? detail_rule_line
          : SIZE_MAX;
  ClampColumn(detail_lines, 1, detail_focus, max_body, right_width);

  const std::string gap = Paint(
      kDividerStyle,
      Repeat(' ', gap_width / 2) + "|" +
          Repeat(' ', gap_width - gap_width / 2 - 1));
  const std::size_t body_rows = std::max(
      catalog_lines.size(), std::max(package_lines.size(), detail_lines.size()));
  for (std::size_t row = 0; row < body_rows; ++row) {
    const std::string left =
        row < catalog_lines.size() ? catalog_lines[row]
                                   : PaintLine(kPanelStyle, "", left_width);
    const std::string middle =
        row < package_lines.size() ? package_lines[row]
                                   : PaintLine(kPanelStyle, "", mid_width);
    const std::string right =
        row < detail_lines.size() ? detail_lines[row]
                                  : PaintLine(kPanelStyle, "", right_width);
    std::cout << left << gap << middle << gap << right << "\n";
  }

  std::cout << "\n";
  std::cout << Paint(
                   status_is_error ? kFooterErrorStyle : kFooterStyle,
                   PadRight(status_message.empty()
                                ? "Catalog view: sync trusted sources, inspect packages, then install/remove without leaving the console."
                                : status_message,
                            total_width));
  std::cout.flush();
}

void DrawSettingsUI(const std::vector<Feature>& features, std::size_t cursor,
                    const std::string& path, bool dirty,
                    const std::string& status_message = "",
                    bool status_is_error = false) {
  const TerminalSize term = GetTerminalSize();
  const std::size_t total_width = std::max<std::size_t>(term.cols, 72);
  const std::size_t enabled_count =
      static_cast<std::size_t>(std::count_if(features.begin(), features.end(),
                                            [](const Feature& feature) {
                                              return feature.enabled;
                                            }));

  std::size_t left_width = std::clamp<std::size_t>(total_width / 3, 28, 36);
  std::size_t gap_width = 3;
  if (left_width + gap_width + 26 > total_width) {
    left_width = total_width > 30 ? total_width / 2 - 1 : total_width;
    gap_width = total_width > 60 ? 3 : 1;
  }
  std::size_t right_width =
      total_width > left_width + gap_width ? total_width - left_width - gap_width : 0;
  if (right_width < 26 && total_width > 26 + gap_width) {
    right_width = 26;
    left_width = total_width - right_width - gap_width;
  }

  const Feature& selected = features[cursor];
  std::vector<std::string> right_lines;
  right_lines.push_back(PaintLine(kPanelSectionStyle, "DETAILS", right_width));
  right_lines.push_back(PaintLine(selected.enabled ? kStatusOnStyle : kStatusOffStyle,
                                  selected.enabled ? " STATUS  ACTIVE"
                                                   : " STATUS  DISABLED",
                                  right_width));
  right_lines.push_back(PaintLine(kPanelStyle, selected.title, right_width));
  right_lines.push_back(PaintLine(kPanelDimStyle,
                                  "Hook: " + selected.hook_name + "  |  " +
                                      selected.env_key,
                                  right_width));
  right_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  right_lines.push_back(PaintLine(kPanelSectionStyle, "WHAT THIS SETTING DOES",
                                  right_width));
  for (const auto& line : WrapText(selected.summary, right_width)) {
    right_lines.push_back(PaintLine(kPanelStyle, line, right_width));
  }
  right_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  right_lines.push_back(PaintLine(kPanelSectionStyle, "WHEN ENABLED", right_width));
  for (const auto& line : WrapText(selected.enabled_effect, right_width)) {
    right_lines.push_back(PaintLine(kPanelStyle, line, right_width));
  }
  right_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  right_lines.push_back(PaintLine(kPanelSectionStyle, "WHEN DISABLED", right_width));
  for (const auto& line : WrapText(selected.disabled_effect, right_width)) {
    right_lines.push_back(PaintLine(kPanelStyle, line, right_width));
  }
  right_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  right_lines.push_back(PaintLine(kPanelSectionStyle, "CONTROLS", right_width));
  right_lines.push_back(PaintLine(kPanelDimStyle, "Space  Toggle selected setting",
                                  right_width));
  right_lines.push_back(PaintLine(kPanelDimStyle, "A      Enable or disable all",
                                  right_width));
  right_lines.push_back(PaintLine(kPanelDimStyle, "S      Save and exit",
                                  right_width));
  right_lines.push_back(PaintLine(kPanelDimStyle, "Q      Quit without saving",
                                  right_width));
  right_lines.push_back(PaintLine(kPanelStyle, "", right_width));
  right_lines.push_back(PaintLine(kPanelSectionStyle, "STATE", right_width));
  right_lines.push_back(PaintLine(kPanelDimStyle,
                                  "Category: " + selected.category, right_width));
  right_lines.push_back(PaintLine(kPanelStyle,
                                  std::to_string(enabled_count) + "/" +
                                      std::to_string(features.size()) +
                                      " settings enabled",
                                  right_width));
  right_lines.push_back(PaintLine(dirty ? kStatusOffStyle : kPanelStyle,
                                  dirty ? " UNSAVED CHANGES PENDING"
                                        : " ALL CHANGES SAVED",
                                  right_width));
  for (const auto& line : WrapText("File: " + path, right_width)) {
    right_lines.push_back(PaintLine(kPanelDimStyle, line, right_width));
  }

  std::cout << "\x1b[2J\x1b[H" << kHideCursor;

  const std::string title = " ASG Policy Console";
  const std::string summary =
      " Settings  " + std::to_string(enabled_count) + "/" +
      std::to_string(features.size()) + " enabled";
  std::string header;
  if (title.size() + summary.size() <= total_width) {
    header = title + Repeat(' ', total_width - title.size() - summary.size()) +
             summary;
  } else {
    header = FitText(title, total_width);
  }
  std::cout << Paint(kHeaderStyle, PadRight(header, total_width)) << "\n";
  std::cout << BuildTabBar(ConsoleView::kSettings, total_width) << "\n\n";

  std::vector<std::string> left_lines;
  left_lines.push_back(PaintLine(kPanelSectionStyle, "SETTINGS", left_width));
  for (std::size_t i = 0; i < features.size(); ++i) {
    const auto& feature = features[i];
    const std::string prefix = i == cursor ? "> " : "  ";
    const std::string plain =
        prefix + (feature.enabled ? "[x] " : "[ ] ") + feature.title;
    if (i == cursor) {
      left_lines.push_back(PaintLine(kSelectedStyle, plain, left_width));
    } else {
      left_lines.push_back(PaintLine(feature.enabled ? kListOnStyle : kListOffStyle,
                                     plain, left_width));
    }
  }

  const std::size_t max_body = term.rows > 5 ? term.rows - 5 : term.rows;
  ClampColumn(left_lines, 1, cursor, max_body, left_width);
  ClampColumn(right_lines, 0, SIZE_MAX, max_body, right_width);

  const std::size_t body_rows = std::max(left_lines.size(), right_lines.size());
  const std::string gap = Paint(kDividerStyle, Repeat(' ', gap_width / 2) + "|" +
                                                   Repeat(' ', gap_width - gap_width / 2 - 1));
  for (std::size_t row = 0; row < body_rows; ++row) {
    const std::string left =
        row < left_lines.size() ? left_lines[row]
                                : PaintLine(kPanelStyle, "", left_width);
    const std::string right =
        row < right_lines.size() ? right_lines[row]
                                 : PaintLine(kPanelStyle, "", right_width);
    std::cout << left << gap << right << "\n";
  }

  std::cout << "\n";
  std::cout << Paint(status_is_error ? kFooterErrorStyle : kFooterStyle,
                     PadRight(status_message.empty()
                                  ? "Legacy runtime toggles live here now. Rules stays the default home."
                                  : status_message,
                              total_width));
  std::cout.flush();
}

class RawMode {
 public:
  RawMode() = default;
  ~RawMode() { Disable(); }

  bool Enable(std::string* error) {
    if (!::isatty(STDIN_FILENO)) {
      if (error != nullptr) {
        *error = "stdin is not a TTY";
      }
      return false;
    }
    if (::tcgetattr(STDIN_FILENO, &original_) != 0) {
      if (error != nullptr) {
        *error = std::string("tcgetattr failed: ") + std::strerror(errno);
      }
      return false;
    }
    termios raw = original_;
    raw.c_lflag &= ~(ECHO | ICANON);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (::tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
      if (error != nullptr) {
        *error = std::string("tcsetattr failed: ") + std::strerror(errno);
      }
      return false;
    }
    enabled_ = true;
    return true;
  }

  void Disable() {
    if (enabled_) {
      (void)::tcsetattr(STDIN_FILENO, TCSAFLUSH, &original_);
      enabled_ = false;
    }
  }

 private:
  termios original_{};
  bool enabled_ = false;
};

class ScreenGuard {
 public:
  ~ScreenGuard() {
    std::cout << kReset << kShowCursor;
    std::cout.flush();
  }
};

enum class KeyPress {
  kNone,
  kUp,
  kDown,
  kLeft,
  kRight,
  kToggle,
  kToggleAll,
  kReset,
  kInstall,
  kRemove,
  kSync,
  kEnter,
  kSave,
  kQuit,
  kNextView,
};

KeyPress ReadKey() {
  char c = 0;
  if (::read(STDIN_FILENO, &c, 1) != 1) {
    return KeyPress::kNone;
  }
  if (c == ' ') {
    return KeyPress::kToggle;
  }
  if (c == 'a' || c == 'A') {
    return KeyPress::kToggleAll;
  }
  if (c == 'r' || c == 'R') {
    return KeyPress::kReset;
  }
  if (c == 'i' || c == 'I') {
    return KeyPress::kInstall;
  }
  if (c == 'x' || c == 'X') {
    return KeyPress::kRemove;
  }
  if (c == 'y' || c == 'Y') {
    return KeyPress::kSync;
  }
  if (c == 's' || c == 'S') {
    return KeyPress::kSave;
  }
  if (c == 'q' || c == 'Q') {
    return KeyPress::kQuit;
  }
  if (c == 'k' || c == 'K') {
    return KeyPress::kUp;
  }
  if (c == 'j' || c == 'J') {
    return KeyPress::kDown;
  }
  if (c == 'h' || c == 'H') {
    return KeyPress::kLeft;
  }
  if (c == 'l' || c == 'L') {
    return KeyPress::kRight;
  }
  if (c == '\n' || c == '\r') {
    return KeyPress::kEnter;
  }
  if (c == '\t') {
    return KeyPress::kNextView;
  }
  if (c == '\x1b') {
    char seq[2] = {0, 0};
    if (::read(STDIN_FILENO, &seq[0], 1) != 1) {
      return KeyPress::kNone;
    }
    if (::read(STDIN_FILENO, &seq[1], 1) != 1) {
      return KeyPress::kNone;
    }
    if (seq[0] == '[' && seq[1] == 'A') {
      return KeyPress::kUp;
    }
    if (seq[0] == '[' && seq[1] == 'B') {
      return KeyPress::kDown;
    }
    if (seq[0] == '[' && seq[1] == 'C') {
      return KeyPress::kRight;
    }
    if (seq[0] == '[' && seq[1] == 'D') {
      return KeyPress::kLeft;
    }
    if (seq[0] == '[' && seq[1] == 'Z') {
      return KeyPress::kNextView;
    }
  }
  return KeyPress::kNone;
}

bool SaveAllState(const std::string& features_path,
                  const std::vector<Feature>& features,
                  const std::vector<sg::PackagePolicyState>& policy_states,
                  bool save_features, bool save_policy, std::string* error) {
  if (save_features) {
    std::string settings_error;
    if (!SaveFeatures(features_path, features, &settings_error)) {
      if (error != nullptr) {
        *error = "settings save failed: " + settings_error;
      }
      return false;
    }
  }

  if (save_policy) {
    std::string policy_error;
    if (!sg::SavePackagePolicyState(policy_states, &policy_error)) {
      if (error != nullptr) {
        *error = "policy save failed: " + policy_error;
      }
      return false;
    }
  }

  return true;
}

void PrintUsage(const char* argv0) {
  std::cout
      << "Usage: " << argv0
      << " [--features-file PATH] [--policy-dir PATH] [--rules-dir PATH] [--print]\n"
         "       [--print-settings] [--print-rules] [--settings]\n"
         "       [--catalog-list] [--catalog-add URL] [--catalog-sync]\n"
         "       [--catalog-search TERM] [--catalog-install PACKAGE]\n"
         "       [--install-package PATH] [--remove-package PACKAGE]\n"
         "       [--set KEY=0|1] [--set-package PACKAGE=MODE]\n"
         "       [--set-rule RULE_ID=MODE|inherit]\n"
         "Default: interactive console. Starts in Rules; Tab switches Rules/Catalog/Settings.\n";
}

}  // namespace

int main(int argc, char** argv) {
  std::string features_path = DefaultFeaturesPath();
  std::optional<std::string> policy_dir_override;
  std::optional<std::string> rules_dir_override;
  bool print_settings = false;
  bool print_rules = false;
  bool start_in_settings = false;
  bool catalog_list = false;
  bool catalog_sync = false;
  std::vector<std::string> catalog_add_urls;
  std::vector<std::string> catalog_search_terms;
  std::vector<std::string> catalog_install_selectors;
  std::vector<std::string> install_package_paths;
  std::vector<std::string> remove_packages;
  std::vector<std::pair<std::string, bool>> feature_overrides;
  std::vector<std::pair<std::string, sg::PackageMode>> package_overrides;
  struct RuleOverrideArg {
    int rule_id = 0;
    std::optional<sg::PackageMode> mode;
  };
  std::vector<RuleOverrideArg> rule_overrides;

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--features-file") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --features-file\n";
        return 2;
      }
      features_path = argv[++i];
      continue;
    }
    if (arg == "--policy-dir") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --policy-dir\n";
        return 2;
      }
      policy_dir_override = argv[++i];
      continue;
    }
    if (arg == "--rules-dir") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --rules-dir\n";
        return 2;
      }
      rules_dir_override = argv[++i];
      continue;
    }
    if (arg == "--print" || arg == "--print-settings") {
      print_settings = true;
      continue;
    }
    if (arg == "--print-rules") {
      print_rules = true;
      continue;
    }
    if (arg == "--settings") {
      start_in_settings = true;
      continue;
    }
    if (arg == "--catalog-list") {
      catalog_list = true;
      continue;
    }
    if (arg == "--catalog-add") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --catalog-add\n";
        return 2;
      }
      catalog_add_urls.push_back(argv[++i]);
      continue;
    }
    if (arg == "--catalog-sync") {
      catalog_sync = true;
      continue;
    }
    if (arg == "--catalog-search") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --catalog-search\n";
        return 2;
      }
      catalog_search_terms.push_back(argv[++i]);
      continue;
    }
    if (arg == "--catalog-install") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --catalog-install\n";
        return 2;
      }
      catalog_install_selectors.push_back(argv[++i]);
      continue;
    }
    if (arg == "--install-package") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --install-package\n";
        return 2;
      }
      install_package_paths.push_back(argv[++i]);
      continue;
    }
    if (arg == "--remove-package") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --remove-package\n";
        return 2;
      }
      remove_packages.push_back(argv[++i]);
      continue;
    }
    if (arg == "--set") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --set\n";
        return 2;
      }
      std::string spec = argv[++i];
      const auto eq = spec.find('=');
      if (eq == std::string::npos) {
        std::cerr << "invalid --set format, expected KEY=0|1\n";
        return 2;
      }
      const auto parsed = ParseBool(spec.substr(eq + 1));
      if (!parsed.has_value()) {
        std::cerr << "invalid bool value in --set, expected 0|1|true|false\n";
        return 2;
      }
      feature_overrides.emplace_back(spec.substr(0, eq), *parsed);
      continue;
    }
    if (arg == "--set-package") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --set-package\n";
        return 2;
      }
      std::string spec = argv[++i];
      const auto eq = spec.find('=');
      if (eq == std::string::npos) {
        std::cerr << "invalid --set-package format, expected PACKAGE=MODE\n";
        return 2;
      }
      const auto mode = ParsePackageMode(spec.substr(eq + 1));
      if (!mode.has_value()) {
        std::cerr << "invalid package mode, expected on|detection_only|off\n";
        return 2;
      }
      package_overrides.emplace_back(spec.substr(0, eq), *mode);
      continue;
    }
    if (arg == "--set-rule") {
      if (i + 1 >= argc) {
        std::cerr << "missing value for --set-rule\n";
        return 2;
      }
      std::string spec = argv[++i];
      const auto eq = spec.find('=');
      if (eq == std::string::npos) {
        std::cerr << "invalid --set-rule format, expected RULE_ID=MODE|inherit\n";
        return 2;
      }
      char* end = nullptr;
      const long parsed_id = std::strtol(spec.substr(0, eq).c_str(), &end, 10);
      if (end == spec.c_str() || *end != '\0' || parsed_id <= 0) {
        std::cerr << "invalid rule id in --set-rule\n";
        return 2;
      }

      RuleOverrideArg override;
      override.rule_id = static_cast<int>(parsed_id);
      const std::string raw_mode = Lower(Trim(spec.substr(eq + 1)));
      if (raw_mode != "inherit" && raw_mode != "default") {
        override.mode = ParsePackageMode(raw_mode);
        if (!override.mode.has_value()) {
          std::cerr << "invalid rule mode, expected on|detection_only|off|inherit\n";
          return 2;
        }
      }
      rule_overrides.push_back(override);
      continue;
    }
    if (arg == "-h" || arg == "--help") {
      PrintUsage(argv[0]);
      return 0;
    }
    std::cerr << "unknown argument: " << arg << "\n";
    PrintUsage(argv[0]);
    return 2;
  }

  if (policy_dir_override.has_value()) {
    ::setenv("SG_POLICY_DIR", policy_dir_override->c_str(), 1);
  }
  if (rules_dir_override.has_value()) {
    ::setenv("SG_RULES_DIR", rules_dir_override->c_str(), 1);
  }

  std::vector<Feature> features = kDefaultFeatures;
  LoadFeatures(features_path, &features);
  const bool had_catalog_mutation =
      !catalog_add_urls.empty() || catalog_sync || !catalog_install_selectors.empty();
  const bool had_package_mutation = !install_package_paths.empty() ||
                                    !remove_packages.empty() ||
                                    !catalog_install_selectors.empty();

  for (const auto& url : catalog_add_urls) {
    std::string add_error;
    if (!sg::AddCatalogSource(url, &add_error)) {
      std::cerr << "catalog add failed: " << add_error << "\n";
      return 1;
    }
  }

  if (catalog_sync) {
    std::string sync_error;
    if (!sg::SyncCatalogSources(&sync_error)) {
      std::cerr << "catalog sync failed: " << sync_error << "\n";
      return 1;
    }
  }

  if (!catalog_install_selectors.empty()) {
    for (const auto& selector : catalog_install_selectors) {
      std::string install_error;
      if (!sg::InstallCatalogPackage(selector, &install_error)) {
        std::cerr << "catalog install failed: " << install_error << "\n";
        return 1;
      }
    }
  }

  if (!install_package_paths.empty() || !remove_packages.empty()) {
    for (const auto& input : install_package_paths) {
      std::string expand_error;
      const auto manifests = ExpandManifestInstallPaths(input, &expand_error);
      if (manifests.empty()) {
        std::cerr << "install failed: " << expand_error << "\n";
        return 1;
      }

      for (const auto& manifest : manifests) {
        std::string install_error;
        if (!sg::InstallPackageManifestFile(manifest, &install_error)) {
          std::cerr << "install failed: " << install_error << "\n";
          return 1;
        }
      }
    }

    for (const auto& package : remove_packages) {
      std::string remove_error;
      if (!sg::RemoveInstalledPackage(package, &remove_error)) {
        std::cerr << "remove failed: " << remove_error << "\n";
        return 1;
      }
    }
  }

  const auto catalogs = sg::LoadCatalogSourceRecords();
  const auto catalog_packages = sg::LoadCatalogPackageRecords();

  if (catalog_list || had_catalog_mutation) {
    PrintCatalogs(catalogs, catalog_packages);
    if (!catalog_search_terms.empty()) {
      for (const auto& term : catalog_search_terms) {
        PrintCatalogSearchResults(SearchCatalogPackages(catalog_packages, term), term);
      }
    }
    if (!print_settings && !print_rules && feature_overrides.empty() &&
        package_overrides.empty() && rule_overrides.empty() &&
        !had_package_mutation && catalog_search_terms.empty()) {
      return 0;
    }
  }

  if (!catalog_search_terms.empty()) {
    if (!catalog_list && !had_catalog_mutation) {
      for (const auto& term : catalog_search_terms) {
        PrintCatalogSearchResults(SearchCatalogPackages(catalog_packages, term), term);
      }
    }
    if (!print_settings && !print_rules && feature_overrides.empty() &&
        package_overrides.empty() && rule_overrides.empty() &&
        !had_package_mutation) {
      return 0;
    }
  }

  std::vector<sg::PackagePolicyState> policy_states = sg::LoadPackagePolicyState();
  const CatalogData catalog = LoadCatalogData();

  if (!feature_overrides.empty() || !package_overrides.empty() ||
      !rule_overrides.empty()) {
    for (const auto& [key, value] : feature_overrides) {
      const int idx = FindFeature(features, key);
      if (idx < 0) {
        std::cerr << "unknown feature key: " << key << "\n";
        return 2;
      }
      features[static_cast<std::size_t>(idx)].enabled = value;
    }

    for (const auto& [package, mode] : package_overrides) {
      SetPackageMode(&policy_states, package, mode);
    }

    for (const auto& override : rule_overrides) {
      const sg::RuleMetadata* rule =
          FindCatalogRuleById(catalog.rules, override.rule_id);
      if (rule == nullptr) {
        std::cerr << "unknown rule id: " << override.rule_id << "\n";
        return 2;
      }
      SetRuleOverride(&policy_states, rule->package, rule->rule_id, override.mode);
    }

    std::string error;
    if (!SaveAllState(features_path, features, policy_states,
                      !feature_overrides.empty(),
                      !package_overrides.empty() || !rule_overrides.empty(),
                      &error)) {
      std::cerr << error << "\n";
      return 1;
    }

    if (!package_overrides.empty() || !rule_overrides.empty()) {
      const auto package_rows =
          BuildPackageRows(catalog, policy_states, sg::LoadRuleStatsSnapshot(),
                           sg::LoadPackageStatsSnapshot());
      PrintRules(package_rows);
    } else {
      PrintFeatures(features_path, features);
    }
    return 0;
  }

  if (print_settings) {
    PrintFeatures(features_path, features);
    if (!print_rules) {
      return 0;
    }
  }

  const auto rule_stats = sg::LoadRuleStatsSnapshot();
  const auto package_stats = sg::LoadPackageStatsSnapshot();
  const auto package_rows =
      BuildPackageRows(catalog, policy_states, rule_stats, package_stats);
  if (print_rules || had_package_mutation) {
    PrintRules(package_rows);
    return 0;
  }

  RawMode raw;
  std::string error;
  if (!raw.Enable(&error)) {
    std::cerr << "interactive mode unavailable: " << error << "\n";
    std::cerr << "Use --print-rules, --print, --set-package, --set-rule, or the --catalog-* commands in non-interactive environments.\n";
    return 1;
  }
  ScreenGuard screen_guard;

  ConsoleView view = start_in_settings ? ConsoleView::kSettings : ConsoleView::kRules;
  RulesUiState rules_ui;
  CatalogUiState catalog_ui;
  std::size_t settings_cursor = 0;
  bool policy_dirty = false;
  bool settings_dirty = false;
  bool saved = false;
  std::string status_message;
  bool status_is_error = false;

  // Auto-sync catalogs that were never synced (e.g. first run after install).
  {
    const auto catalogs = sg::LoadCatalogSourceRecords();
    bool has_unsynced = false;
    for (const auto& c : catalogs) {
      if (c.last_synced_at == 0) {
        has_unsynced = true;
        break;
      }
    }
    if (has_unsynced) {
      (void)sg::SyncCatalogSources(nullptr);
    }
  }

  while (true) {
    const CatalogData live_catalog_data = LoadCatalogData();
    const auto live_rule_stats = sg::LoadRuleStatsSnapshot();
    const auto live_package_stats = sg::LoadPackageStatsSnapshot();
    const auto live_catalogs = sg::LoadCatalogSourceRecords();
    const auto live_catalog_packages = sg::LoadCatalogPackageRecords();
    const auto live_installed_packages = sg::LoadInstalledPackageRecords();
    const auto live_packages =
        BuildPackageRows(live_catalog_data, policy_states, live_rule_stats,
                         live_package_stats);
    const auto live_catalog_rows = BuildCatalogPackageRows(
        live_catalogs, live_catalog_packages, live_installed_packages, catalog_ui);
    ClampRulesUiState(live_packages, &rules_ui);
    ClampCatalogUiState(live_catalogs, live_catalog_rows, &catalog_ui);
    const bool dirty = policy_dirty || settings_dirty;

    if (view == ConsoleView::kRules) {
      DrawRulesUI(live_packages, rules_ui, dirty, status_message, status_is_error);
    } else if (view == ConsoleView::kCatalog) {
      DrawCatalogUI(live_catalogs, live_catalog_rows, catalog_ui, dirty,
                    policy_states, status_message, status_is_error);
    } else {
      if (settings_cursor >= features.size()) {
        settings_cursor = features.empty() ? 0 : features.size() - 1;
      }
      DrawSettingsUI(features, settings_cursor, features_path, dirty, status_message,
                     status_is_error);
    }

    const KeyPress key = ReadKey();
    if (key == KeyPress::kNextView) {
      view = view == ConsoleView::kRules
                 ? ConsoleView::kCatalog
                 : (view == ConsoleView::kCatalog ? ConsoleView::kSettings
                                                  : ConsoleView::kRules);
      status_message.clear();
      status_is_error = false;
      continue;
    }
    if (key == KeyPress::kQuit) {
      break;
    }
    if (key == KeyPress::kSave) {
      std::string save_error;
      if (!SaveAllState(features_path, features, policy_states, settings_dirty,
                        policy_dirty, &save_error)) {
        status_message = save_error;
        status_is_error = true;
        continue;
      }
      policy_dirty = false;
      settings_dirty = false;
      saved = true;
      break;
    }

    if (view == ConsoleView::kSettings) {
      if (key == KeyPress::kUp) {
        if (settings_cursor == 0) {
          settings_cursor = features.size() - 1;
        } else {
          --settings_cursor;
        }
        status_message.clear();
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kDown) {
        settings_cursor = (settings_cursor + 1) % features.size();
        status_message.clear();
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kToggle) {
        features[settings_cursor].enabled = !features[settings_cursor].enabled;
        settings_dirty = true;
        status_message = features[settings_cursor].title +
                         (features[settings_cursor].enabled ? " enabled"
                                                            : " disabled");
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kToggleAll) {
        const bool any_disabled =
            std::any_of(features.begin(), features.end(),
                        [](const Feature& f) { return !f.enabled; });
        for (auto& feature : features) {
          feature.enabled = any_disabled;
        }
        settings_dirty = true;
        status_message =
            any_disabled ? "All settings enabled" : "All settings disabled";
        status_is_error = false;
        continue;
      }
      continue;
    }

    if (view == ConsoleView::kCatalog) {
      // Resolve selected package's rule count for navigation bounds.
      const std::size_t sel_pkg_rule_count =
          (!live_catalog_rows.empty() &&
           catalog_ui.package_cursor < live_catalog_rows.size())
              ? live_catalog_rows[catalog_ui.package_cursor]
                    .package.rules.size()
              : 0;

      if (key == KeyPress::kLeft) {
        if (catalog_ui.active_pane == CatalogPane::kRules) {
          catalog_ui.active_pane = CatalogPane::kPackages;
        } else {
          catalog_ui.active_pane = CatalogPane::kSources;
        }
        status_message.clear();
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kRight) {
        if (catalog_ui.active_pane == CatalogPane::kSources &&
            !live_catalog_rows.empty()) {
          catalog_ui.active_pane = CatalogPane::kPackages;
        } else if (catalog_ui.active_pane == CatalogPane::kPackages &&
                   sel_pkg_rule_count > 0) {
          catalog_ui.active_pane = CatalogPane::kRules;
          catalog_ui.rule_cursor = 0;
        }
        status_message.clear();
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kUp) {
        if (catalog_ui.active_pane == CatalogPane::kSources) {
          if (!live_catalogs.empty()) {
            if (catalog_ui.source_cursor == 0) {
              catalog_ui.source_cursor = live_catalogs.size() - 1;
            } else {
              --catalog_ui.source_cursor;
            }
            catalog_ui.package_cursor = 0;
          }
        } else if (catalog_ui.active_pane == CatalogPane::kPackages) {
          if (!live_catalog_rows.empty()) {
            if (catalog_ui.package_cursor == 0) {
              catalog_ui.package_cursor = live_catalog_rows.size() - 1;
            } else {
              --catalog_ui.package_cursor;
            }
            catalog_ui.rule_cursor = 0;
          }
        } else if (catalog_ui.active_pane == CatalogPane::kRules) {
          if (sel_pkg_rule_count > 0) {
            if (catalog_ui.rule_cursor == 0) {
              catalog_ui.rule_cursor = sel_pkg_rule_count - 1;
            } else {
              --catalog_ui.rule_cursor;
            }
          }
        }
        status_message.clear();
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kDown) {
        if (catalog_ui.active_pane == CatalogPane::kSources) {
          if (!live_catalogs.empty()) {
            catalog_ui.source_cursor =
                (catalog_ui.source_cursor + 1) % live_catalogs.size();
            catalog_ui.package_cursor = 0;
          }
        } else if (catalog_ui.active_pane == CatalogPane::kPackages) {
          if (!live_catalog_rows.empty()) {
            catalog_ui.package_cursor =
                (catalog_ui.package_cursor + 1) % live_catalog_rows.size();
            catalog_ui.rule_cursor = 0;
          }
        } else if (catalog_ui.active_pane == CatalogPane::kRules) {
          if (sel_pkg_rule_count > 0) {
            catalog_ui.rule_cursor =
                (catalog_ui.rule_cursor + 1) % sel_pkg_rule_count;
          }
        }
        status_message.clear();
        status_is_error = false;
        continue;
      }
      const bool enter_as_sync =
          key == KeyPress::kEnter &&
          catalog_ui.active_pane == CatalogPane::kSources;
      const bool enter_as_install =
          key == KeyPress::kEnter &&
          catalog_ui.active_pane == CatalogPane::kPackages;
      const bool enter_as_rule_toggle =
          key == KeyPress::kEnter &&
          catalog_ui.active_pane == CatalogPane::kRules;
      if (enter_as_rule_toggle) {
        if (live_catalog_rows.empty() ||
            catalog_ui.package_cursor >= live_catalog_rows.size()) {
          continue;
        }
        const auto& pkg = live_catalog_rows[catalog_ui.package_cursor];
        if (catalog_ui.rule_cursor >= pkg.package.rules.size()) {
          continue;
        }
        const auto& rule = pkg.package.rules[catalog_ui.rule_cursor];
        const auto cur_mode = sg::FindRuleModeOverride(
            policy_states, pkg.package.package, rule.rule_id);
        // Simple toggle: if currently off, set on; otherwise set off.
        const bool currently_off =
            cur_mode.has_value() && *cur_mode == sg::PackageMode::kOff;
        const auto new_mode = currently_off
                                  ? std::optional<sg::PackageMode>(sg::PackageMode::kOn)
                                  : std::optional<sg::PackageMode>(sg::PackageMode::kOff);
        SetRuleOverride(&policy_states, pkg.package.package, rule.rule_id,
                        new_mode);
        policy_dirty = true;
        const std::string action_label = currently_off ? "enabled" : "disabled";
        status_message = std::to_string(rule.rule_id) + " " + rule.name +
                         " " + action_label;
        status_is_error = false;
        // Audit: log rule override to events.jsonl + stderr (journal).
        {
          std::ostringstream ev;
          ev << "{\"event_type\":\"rule_override\",\"timestamp\":"
             << sg::UnixNow()
             << ",\"package\":\"" << sg::JsonEscape(pkg.package.package) << "\""
             << ",\"rule_id\":" << rule.rule_id
             << ",\"rule_name\":\"" << sg::JsonEscape(rule.name) << "\""
             << ",\"action\":\"" << action_label << "\""
             << ",\"new_mode\":\"" << sg::ToString(
                    new_mode.value_or(sg::PackageMode::kOn)) << "\""
             << "}";
          sg::AppendEventLine(sg::DefaultEventsFilePath(), ev.str());
          std::cerr << "asg-cli: RULE_OVERRIDE " << action_label
                    << " rule=" << rule.rule_id
                    << " (" << rule.name << ")"
                    << " package=" << pkg.package.package << "\n";
        }
        continue;
      }
      if (key == KeyPress::kSync || enter_as_sync) {
        // Show syncing status immediately before blocking fetch.
        status_message = "Syncing catalogs...";
        status_is_error = false;
        DrawCatalogUI(live_catalogs, live_catalog_rows, catalog_ui, dirty,
                      policy_states, status_message, status_is_error);
        std::string sync_error;
        if (!sg::SyncCatalogSources(&sync_error)) {
          status_message = "Sync failed: " + sync_error;
          status_is_error = true;
          continue;
        }
        status_message = "Catalog sync complete";
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kInstall || enter_as_install) {
        if (live_catalog_rows.empty()) {
          status_message = "No catalog package selected";
          status_is_error = false;
          continue;
        }
        const auto& package = live_catalog_rows[catalog_ui.package_cursor];
        const std::string selector = package.package.catalog_id.empty()
                                         ? package.package.package
                                         : package.package.catalog_id + ":" +
                                               package.package.package;
        std::string install_error;
        if (!sg::InstallCatalogPackage(selector, &install_error)) {
          status_message = "catalog install failed: " + install_error;
          status_is_error = true;
          continue;
        }
        status_message =
            (package.installed ? "Updated " : "Installed ") + package.package.title;
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kRemove) {
        if (live_catalog_rows.empty()) {
          status_message = "No catalog package selected";
          status_is_error = false;
          continue;
        }
        const auto& package = live_catalog_rows[catalog_ui.package_cursor];
        if (!package.installed) {
          status_message = package.package.title + " is not installed";
          status_is_error = false;
          continue;
        }
        std::string remove_error;
        if (!sg::RemoveInstalledPackage(package.package.package, &remove_error)) {
          status_message = "remove failed: " + remove_error;
          status_is_error = true;
          continue;
        }
        status_message = "Removed " + package.package.title;
        status_is_error = false;
        continue;
      }
      if (key == KeyPress::kToggle || key == KeyPress::kReset ||
          key == KeyPress::kToggleAll) {
        status_message =
            "Catalog uses Y to sync, I to install/update, and X to remove";
        status_is_error = false;
      }
      continue;
    }

    const auto& live_selected_packages = live_packages;
    if (live_selected_packages.empty()) {
      status_message = "No packages available";
      status_is_error = true;
      continue;
    }

    if (key == KeyPress::kLeft) {
      rules_ui.active_pane = RulesPane::kPackages;
      status_message.clear();
      status_is_error = false;
      continue;
    }
    if (key == KeyPress::kRight) {
      if (!live_selected_packages[rules_ui.package_cursor].rules.empty()) {
        rules_ui.active_pane = RulesPane::kRules;
      }
      status_message.clear();
      status_is_error = false;
      continue;
    }
    if (key == KeyPress::kUp) {
      if (rules_ui.active_pane == RulesPane::kPackages) {
        if (rules_ui.package_cursor == 0) {
          rules_ui.package_cursor = live_selected_packages.size() - 1;
        } else {
          --rules_ui.package_cursor;
        }
      } else {
        const auto& rules = live_selected_packages[rules_ui.package_cursor].rules;
        if (!rules.empty()) {
          if (rules_ui.rule_cursor == 0) {
            rules_ui.rule_cursor = rules.size() - 1;
          } else {
            --rules_ui.rule_cursor;
          }
        }
      }
      status_message.clear();
      status_is_error = false;
      continue;
    }
    if (key == KeyPress::kDown) {
      if (rules_ui.active_pane == RulesPane::kPackages) {
        rules_ui.package_cursor =
            (rules_ui.package_cursor + 1) % live_selected_packages.size();
      } else {
        const auto& rules = live_selected_packages[rules_ui.package_cursor].rules;
        if (!rules.empty()) {
          rules_ui.rule_cursor = (rules_ui.rule_cursor + 1) % rules.size();
        }
      }
      status_message.clear();
      status_is_error = false;
      continue;
    }
    if (key == KeyPress::kToggleAll) {
      status_message = "A is only used in Settings";
      status_is_error = false;
      continue;
    }
    if (key == KeyPress::kReset) {
      if (rules_ui.active_pane != RulesPane::kRules) {
        status_message = "Select a rule to reset its override";
        status_is_error = false;
        continue;
      }

      const auto& package = live_selected_packages[rules_ui.package_cursor];
      if (package.rules.empty()) {
        status_message = "No rule override to reset";
        status_is_error = false;
        continue;
      }

      const auto& rule = package.rules[rules_ui.rule_cursor];
      if (!rule.has_override) {
        status_message = "Selected rule already inherits package mode";
        status_is_error = false;
        continue;
      }

      SetRuleOverride(&policy_states, package.info.package, rule.meta.rule_id,
                      std::nullopt);
      policy_dirty = true;
      status_message =
          std::to_string(rule.meta.rule_id) + " now inherits package mode";
      status_is_error = false;
      // Audit: log rule reset.
      {
        std::ostringstream ev;
        ev << "{\"event_type\":\"rule_override\",\"timestamp\":"
           << sg::UnixNow()
           << ",\"package\":\"" << sg::JsonEscape(package.info.package) << "\""
           << ",\"rule_id\":" << rule.meta.rule_id
           << ",\"rule_name\":\"" << sg::JsonEscape(rule.meta.name) << "\""
           << ",\"action\":\"reset\""
           << ",\"new_mode\":\"inherit\""
           << "}";
        sg::AppendEventLine(sg::DefaultEventsFilePath(), ev.str());
        std::cerr << "asg-cli: RULE_OVERRIDE reset"
                  << " rule=" << rule.meta.rule_id
                  << " (" << rule.meta.name << ")"
                  << " package=" << package.info.package << "\n";
      }
      continue;
    }
    if (key == KeyPress::kToggle) {
      const auto& package = live_selected_packages[rules_ui.package_cursor];
      if (rules_ui.active_pane == RulesPane::kPackages) {
        const sg::PackageMode next_mode = NextPackageMode(package.mode);
        SetPackageMode(&policy_states, package.info.package, next_mode);
        policy_dirty = true;
        status_message =
            package.info.title + " set to " + LongModeLabel(next_mode);
        status_is_error = false;
        continue;
      }

      if (package.rules.empty()) {
        status_message = "Selected package has no rules";
        status_is_error = false;
        continue;
      }

      const auto& rule = package.rules[rules_ui.rule_cursor];
      const auto next_override = NextRuleOverride(package, rule);
      SetRuleOverride(&policy_states, package.info.package, rule.meta.rule_id,
                      next_override);
      policy_dirty = true;
      const std::string mode_label = next_override.has_value()
                                         ? std::string(sg::ToString(*next_override))
                                         : "inherit";
      if (next_override.has_value()) {
        status_message = std::to_string(rule.meta.rule_id) + " set to " +
                         LongModeLabel(*next_override);
      } else {
        status_message = std::to_string(rule.meta.rule_id) +
                         " now inherits package mode";
      }
      status_is_error = false;
      // Audit: log rule override.
      {
        std::ostringstream ev;
        ev << "{\"event_type\":\"rule_override\",\"timestamp\":"
           << sg::UnixNow()
           << ",\"package\":\"" << sg::JsonEscape(package.info.package) << "\""
           << ",\"rule_id\":" << rule.meta.rule_id
           << ",\"rule_name\":\"" << sg::JsonEscape(rule.meta.name) << "\""
           << ",\"action\":\"set\""
           << ",\"new_mode\":\"" << mode_label << "\""
           << "}";
        sg::AppendEventLine(sg::DefaultEventsFilePath(), ev.str());
        std::cerr << "asg-cli: RULE_OVERRIDE " << mode_label
                  << " rule=" << rule.meta.rule_id
                  << " (" << rule.meta.name << ")"
                  << " package=" << package.info.package << "\n";
      }
      continue;
    }
  }

  raw.Disable();
  std::cout << "\x1b[2J\x1b[H" << kReset << kShowCursor;
  if (saved) {
    std::cout << "asg-cli: saved " << sg::DefaultPolicyDir().string() << " and "
              << features_path << "\n";
  } else {
    std::cout << "asg-cli: no changes saved\n";
  }
  return 0;
}
