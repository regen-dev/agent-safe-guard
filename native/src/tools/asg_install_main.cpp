#include "sg/process.hpp"
#include "sg/policy_state.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct FeatureDef {
  const char* key;
  const char* label;
  const char* description;
  const char* default_value;
};

constexpr FeatureDef kFeatures[] = {
    {"SG_FEATURE_PRE_TOOL_USE", "PreToolUse",
     "Block dangerous commands and enforce budgets", "1"},
    {"SG_FEATURE_POST_TOOL_USE", "PostToolUse",
     "Truncate and normalize tool outputs", "1"},
    {"SG_FEATURE_READ_GUARD", "ReadGuard",
     "Block bundled or oversized file reads", "1"},
    {"SG_FEATURE_READ_COMPRESS", "ReadCompress",
     "Keep large Read outputs structural", "1"},
    {"SG_FEATURE_PERMISSION_REQUEST", "PermissionRequest",
     "Auto-allow and auto-deny permission prompts", "1"},
    {"SG_FEATURE_SESSION_START", "SessionStart",
     "Initialize session tracking files", "1"},
    {"SG_FEATURE_SESSION_END", "SessionEnd",
     "Finalize sessions and clean state", "1"},
    {"SG_FEATURE_SUBAGENT_START", "SubagentStart",
     "Check subagent budgets and inject guidance", "1"},
    {"SG_FEATURE_SUBAGENT_STOP", "SubagentStop",
     "Reclaim subagent budget and track duration", "1"},
    {"SG_FEATURE_STOP", "Stop", "Emit stop summary and block counts", "1"},
    {"SG_FEATURE_PRE_COMPACT", "PreCompact",
     "Inject compact-state summary before compaction", "1"},
    {"SG_FEATURE_TOOL_ERROR", "ToolError",
     "Log hook errors and add recovery hints", "1"},
    {"SG_FEATURE_STATUSLINE", "StatusLine", "Render the terminal status line",
     "0"},
    {"SG_FEATURE_REPOMAP", "Repomap",
     "Inject a ranked repo-map into SessionStart additionalContext", "1"},
};

struct HookDef {
  const char* logical_name;
  const char* launcher_name;
  const char* native_name;
};

constexpr HookDef kHooks[] = {
    {"pre-tool-use", "asg-pre-tool-use", "sg-hook-pre-tool-use"},
    {"post-tool-use", "asg-post-tool-use", "sg-hook-post-tool-use"},
    {"read-guard", "asg-read-guard", "sg-hook-read-guard"},
    {"read-compress", "asg-read-compress", "sg-hook-read-compress"},
    {"permission-request", "asg-permission-request",
     "sg-hook-permission-request"},
    {"session-start", "asg-session-start", "sg-hook-session-start"},
    {"session-end", "asg-session-end", "sg-hook-session-end"},
    {"subagent-start", "asg-subagent-start", "sg-hook-subagent-start"},
    {"subagent-stop", "asg-subagent-stop", "sg-hook-subagent-stop"},
    {"stop", "asg-stop", "sg-hook-stop"},
    {"pre-compact", "asg-pre-compact", "sg-hook-pre-compact"},
    {"tool-error", "asg-tool-error", "sg-hook-tool-error"},
};

enum class FeatureUiMode { kAuto, kForce, kOff };

struct Options {
  bool explicit_native = false;
  bool enable_systemd_user = true;
  bool auto_build_native = true;
  FeatureUiMode feature_ui = FeatureUiMode::kAuto;
  std::string native_bin_dir;
};

constexpr std::string_view kSystemdSocketUnitName = "asg.socket";
constexpr std::string_view kSystemdServiceUnitName = "asg.service";
constexpr std::string_view kLegacySystemdSocketUnitName =
    "agent-safe-guard-sgd.socket";
constexpr std::string_view kLegacySystemdServiceUnitName =
    "agent-safe-guard-sgd.service";

std::string Green() { return "\033[32m"; }
std::string Yellow() { return "\033[33m"; }
std::string Red() { return "\033[31m"; }
std::string Reset() { return "\033[0m"; }

void Info(const std::string& text) {
  std::cout << Green() << "[+]" << Reset() << " " << text << "\n";
}

void Warn(const std::string& text) {
  std::cout << Yellow() << "[!]" << Reset() << " " << text << "\n";
}

int Error(const std::string& text) {
  std::cerr << Red() << "[x]" << Reset() << " " << text << "\n";
  return 1;
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

std::filesystem::path ReadSelfPath() {
  std::vector<char> buffer(4096);
  const ssize_t len =
      ::readlink("/proc/self/exe", buffer.data(), buffer.size() - 1);
  if (len <= 0) {
    return {};
  }
  buffer[static_cast<std::size_t>(len)] = '\0';
  return std::filesystem::path(buffer.data());
}

std::filesystem::path SourceRoot() { return std::filesystem::path(SG_SOURCE_ROOT); }

std::string Home() {
  const char* home = std::getenv("HOME");
  return home != nullptr ? std::string(home) : std::string();
}

std::filesystem::path ClaudeDir() {
  return std::filesystem::path(Home()) / ".claude";
}

std::filesystem::path ConfigDir() { return ClaudeDir() / ".safeguard"; }

std::filesystem::path FeaturesFile() { return ConfigDir() / "features.env"; }

std::filesystem::path SettingsFile() { return ClaudeDir() / "settings.json"; }

std::filesystem::path HooksDir() { return ClaudeDir() / "hooks"; }

std::filesystem::path LocalBinDir() {
  return std::filesystem::path(Home()) / ".local/bin";
}

std::filesystem::path SystemdUserDir() {
  return std::filesystem::path(Home()) / ".config/systemd/user";
}

void RemoveSystemdUnit(std::string_view unit_name) {
  sg::RunProcess(
      {"systemctl", "--user", "disable", "--now", std::string(unit_name)});
  std::error_code ec;
  std::filesystem::remove(SystemdUserDir() / std::string(unit_name), ec);
}

void CleanupLegacySystemdUnits() {
  std::error_code ec;
  const auto legacy_socket =
      SystemdUserDir() / std::string(kLegacySystemdSocketUnitName);
  const auto legacy_service =
      SystemdUserDir() / std::string(kLegacySystemdServiceUnitName);
  if (!std::filesystem::exists(legacy_socket, ec) &&
      !std::filesystem::exists(legacy_service, ec)) {
    return;
  }

  Info("Removing legacy user units: agent-safe-guard-sgd.socket, "
       "agent-safe-guard-sgd.service");
  RemoveSystemdUnit(kLegacySystemdSocketUnitName);
  RemoveSystemdUnit(kLegacySystemdServiceUnitName);
}

std::optional<std::filesystem::path> FindInPath(const std::string& name) {
  const char* path_env = std::getenv("PATH");
  if (path_env == nullptr) {
    return std::nullopt;
  }
  for (const auto& entry : std::vector<std::string>([&]() {
         std::vector<std::string> parts;
         std::string current;
         for (char ch : std::string(path_env)) {
           if (ch == ':') {
             parts.push_back(current);
             current.clear();
           } else {
             current.push_back(ch);
           }
         }
         parts.push_back(current);
         return parts;
       }())) {
    if (entry.empty()) {
      continue;
    }
    auto candidate = std::filesystem::path(entry) / name;
    std::error_code ec;
    if (std::filesystem::exists(candidate, ec) &&
        ::access(candidate.c_str(), X_OK) == 0) {
      return candidate;
    }
  }
  return std::nullopt;
}

std::optional<std::filesystem::path> ResolveNativeBin(const Options& options,
                                                      const std::string& name) {
  const auto self_dir = ReadSelfPath().parent_path();
  const std::vector<std::filesystem::path> candidates = {
      options.native_bin_dir.empty() ? std::filesystem::path()
                                     : std::filesystem::path(options.native_bin_dir),
      self_dir,
      SourceRoot() / "build/native/native",
  };
  for (const auto& dir : candidates) {
    if (dir.empty()) {
      continue;
    }
    const auto candidate = dir / name;
    if (::access(candidate.c_str(), X_OK) == 0) {
      return candidate;
    }
  }
  return FindInPath(name);
}

bool ParseFeatureBool(std::string_view raw, bool fallback = true) {
  std::string lowered = Trim(raw);
  for (char& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  if (lowered == "1" || lowered == "true" || lowered == "on" ||
      lowered == "yes" || lowered == "y") {
    return true;
  }
  if (lowered == "0" || lowered == "false" || lowered == "off" ||
      lowered == "no" || lowered == "n") {
    return false;
  }
  return fallback;
}

std::optional<bool> TryParseFeatureBool(std::string_view raw) {
  const std::string trimmed = Trim(raw);
  if (trimmed.empty()) {
    return std::nullopt;
  }
  const bool parsed = ParseFeatureBool(trimmed, true);
  const bool reparsed = ParseFeatureBool(trimmed, false);
  if (parsed == reparsed) {
    return parsed;
  }
  return std::nullopt;
}

std::map<std::string, std::string> LoadFeatureValues() {
  std::map<std::string, std::string> values;
  for (const auto& feature : kFeatures) {
    values[feature.key] = feature.default_value;
  }
  std::ifstream in(FeaturesFile());
  if (!in) {
    return values;
  }
  for (std::string line; std::getline(in, line);) {
    if (line.empty() || line.front() == '#') {
      continue;
    }
    const auto eq = line.find('=');
    if (eq == std::string::npos) {
      continue;
    }
    const std::string key = Trim(line.substr(0, eq));
    const std::string value = Trim(line.substr(eq + 1));
    if (values.find(key) != values.end()) {
      values[key] = ParseFeatureBool(value) ? "1" : "0";
    }
  }
  return values;
}

bool SaveFeatureValues(const std::map<std::string, std::string>& values) {
  std::error_code ec;
  std::filesystem::create_directories(FeaturesFile().parent_path(), ec);
  std::ofstream out(FeaturesFile(), std::ios::trunc);
  if (!out) {
    return false;
  }
  out << "# agent-safe-guard feature toggles\n";
  out << "# 1=enabled, 0=disabled\n";
  for (const auto& feature : kFeatures) {
    const auto it = values.find(feature.key);
    out << feature.key << "="
        << (it != values.end() ? it->second : feature.default_value) << "\n";
  }
  return static_cast<bool>(out);
}

bool IsInteractiveTty() { return ::isatty(STDIN_FILENO) && ::isatty(STDOUT_FILENO); }

bool ShouldRunFeatureUi(FeatureUiMode mode) {
  if (mode == FeatureUiMode::kForce) {
    return true;
  }
  if (mode == FeatureUiMode::kOff) {
    return false;
  }
  return IsInteractiveTty();
}

bool RunPromptSelector() {
  auto values = LoadFeatureValues();
  std::cout << "\nFeature setup\n";
  std::cout << "Press Enter to keep the current value.\n";
  for (const auto& feature : kFeatures) {
    std::cout << "\n" << feature.label << "\n  " << feature.description << "\n";
    while (true) {
      const bool current = values[feature.key] == "1";
      std::cout << "  Enable " << feature.label << "? "
                << (current ? "[Y/n] " : "[y/N] ");
      std::string answer;
      if (!std::getline(std::cin, answer)) {
        return false;
      }
      answer = Trim(answer);
      if (answer.empty()) {
        break;
      }
      const auto enabled = TryParseFeatureBool(answer);
      if (!enabled.has_value()) {
        std::cout << "  Please answer y or n.\n";
        continue;
      }
      values[feature.key] = *enabled ? "1" : "0";
      break;
    }
  }
  return SaveFeatureValues(values);
}

bool RunFeaturePanel(const Options& options) {
  const auto asg_cli = ResolveNativeBin(options, "asg-cli");
  if (IsInteractiveTty() && asg_cli.has_value()) {
    Info("Opening feature panel...");
    const int exit_code = sg::SpawnAndWait(
        {asg_cli->string(), "--features-file", FeaturesFile().string()});
    return exit_code == 0;
  }
  Warn(IsInteractiveTty() ? "asg-cli unavailable; falling back to prompt selector"
                          : "feature panel requires a TTY; falling back to prompt selector");
  return RunPromptSelector();
}

bool InstallDefaultFeaturesFile() {
  if (std::filesystem::exists(FeaturesFile())) {
    Info("  features.env preserved");
    return true;
  }
  const auto values = LoadFeatureValues();
  if (!SaveFeatureValues(values)) {
    return false;
  }
  Info("  features.env installed (defaults)");
  return true;
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text) {
  std::error_code ec;
  std::filesystem::create_directories(path.parent_path(), ec);
  std::ofstream out(path, std::ios::trunc | std::ios::binary);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

bool CopyFileIfMissing(const std::filesystem::path& from,
                       const std::filesystem::path& to) {
  if (std::filesystem::exists(to)) {
    return true;
  }
  std::error_code ec;
  std::filesystem::create_directories(to.parent_path(), ec);
  std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
  return !ec;
}

bool EnsureNativeBinaries(const Options& options) {
  std::vector<std::string> required = {
      "sgd",         "sg-hook-pre-tool-use",  "sg-hook-post-tool-use",
      "sg-hook-read-guard", "sg-hook-read-compress",
      "sg-hook-permission-request", "sg-hook-stop",
      "sg-hook-session-start", "sg-hook-session-end",
      "sg-hook-pre-compact", "sg-hook-subagent-start",
      "sg-hook-subagent-stop", "sg-hook-tool-error", "asg-cli",
      "asg-statusline", "asg-install", "asg-uninstall",
#ifdef SG_HAS_REPOMAP
      "asg-repomap",
#endif
  };

  std::vector<std::string> missing;
  for (const auto& name : required) {
    if (!ResolveNativeBin(options, name).has_value()) {
      missing.push_back(name);
    }
  }
  if (missing.empty()) {
    return true;
  }
  if (!options.auto_build_native) {
    return false;
  }

  Info("Native binaries missing; building native runtime...");
  const auto configure = sg::RunProcess(
      {"cmake", "-S", SourceRoot().string(), "-B",
       (SourceRoot() / "build/native").string(), "-DSG_BUILD_NATIVE=ON"});
  if (configure.exit_code != 0) {
    std::cerr << configure.stdout_text << configure.stderr_text;
    return false;
  }
  const auto build = sg::RunProcess(
      {"cmake", "--build", (SourceRoot() / "build/native").string(), "-j"});
  if (build.exit_code != 0) {
    std::cerr << build.stdout_text << build.stderr_text;
    return false;
  }

  missing.clear();
  for (const auto& name : required) {
    if (!ResolveNativeBin(options, name).has_value()) {
      missing.push_back(name);
    }
  }
  return missing.empty();
}

void RemoveManagedHookIfPresent(const std::filesystem::path& path) {
  std::error_code ec;
  if (std::filesystem::is_symlink(path, ec)) {
    std::filesystem::remove(path, ec);
    return;
  }
  std::ifstream in(path);
  if (!in) {
    return;
  }
  std::string text((std::istreambuf_iterator<char>(in)),
                   std::istreambuf_iterator<char>());
  if (text.find("# asg-generated: agent-safe-guard-") != std::string::npos ||
      text.find("# sg-generated: agent-safe-guard-") != std::string::npos) {
    std::filesystem::remove(path, ec);
  }
}

bool InstallSymlink(const std::filesystem::path& link_path,
                    const std::filesystem::path& target) {
  std::error_code ec;
  std::filesystem::create_directories(link_path.parent_path(), ec);
  std::filesystem::remove(link_path, ec);
  std::filesystem::create_symlink(target, link_path, ec);
  return !ec;
}

bool ValidateJson(const std::filesystem::path& path) {
  const auto result = sg::RunProcess({"jq", "empty", path.string()});
  return result.exit_code == 0;
}

bool UpdateSettingsJson() {
  const auto settings = SettingsFile();
  const auto backup =
      settings.string() + ".bak." + std::to_string(static_cast<long long>(time(nullptr)));

  if (std::filesystem::exists(settings)) {
    std::error_code ec;
    std::filesystem::copy_file(settings, backup,
                               std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
      return false;
    }
    Info("  Backup: " + backup);
  } else if (!WriteTextFile(settings, "{}\n")) {
    return false;
  }

  if (!ValidateJson(settings)) {
    return false;
  }

  const std::string hooks_json = R"JSON({
  "PreToolUse": [
    {"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-pre-tool-use", "timeout": 10}]},
    {"matcher": "Read", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-read-guard", "timeout": 10}]}
  ],
  "PostToolUse": [
    {"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-post-tool-use", "timeout": 10}]},
    {"matcher": "Read", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-read-compress", "timeout": 10}]}
  ],
  "PermissionRequest": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-permission-request", "timeout": 10}]}],
  "Stop": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-stop", "timeout": 10}]}],
  "SubagentStart": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-subagent-start", "timeout": 10}]}],
  "SubagentStop": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-subagent-stop", "timeout": 10}]}],
  "SessionStart": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-session-start", "timeout": 10}]}],
  "SessionEnd": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-session-end", "timeout": 10}]}],
  "PostToolUseFailure": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-tool-error", "timeout": 10}]}],
  "PreCompact": [{"matcher": "*", "hooks": [{"type": "command", "command": "~/.claude/hooks/asg-pre-compact", "timeout": 10}]}]
})JSON";
  const std::string filter = R"JQ(
  .hooks = (
    (.hooks // {}) |
    reduce ($asg_hooks | keys[]) as $ht (
      .;
      (.[$ht] // []) as $current |
      ($asg_hooks[$ht]) as $asg_entries |
      ($current | map(select(
        (.hooks // []) | all(.command | (test("asg-") or test("sg-") or test("safeguard")) | not)
      ))) as $user_entries |
      .[$ht] = ($user_entries + $asg_entries)
    )
  ) |
  .statusLine = {"type": "command", "command": "~/.local/bin/asg-statusline"}
  )JQ";

  const auto merged = sg::RunProcess(
      {"jq", "--argjson", "asg_hooks", hooks_json, filter, settings.string()});
  if (merged.exit_code != 0) {
    std::cerr << merged.stdout_text << merged.stderr_text;
    return false;
  }
  const auto tmp = settings.string() + ".tmp";
  if (!WriteTextFile(tmp, merged.stdout_text) || !ValidateJson(tmp)) {
    std::error_code ec;
    std::filesystem::remove(tmp, ec);
    return false;
  }
  std::error_code ec;
  std::filesystem::rename(tmp, settings, ec);
  if (ec) {
    std::filesystem::remove(tmp, ec);
    return false;
  }
  Info("  settings.json updated");
  return true;
}

void InstallSystemdUnits(const Options& options) {
  const auto sgd = ResolveNativeBin(options, "sgd");
  if (!sgd.has_value()) {
    Warn("native daemon binary not found; skipping systemd user unit setup");
    return;
  }
  std::error_code ec;
  std::filesystem::create_directories(SystemdUserDir(), ec);
  CleanupLegacySystemdUnits();

  const auto socket_unit = SystemdUserDir() / std::string(kSystemdSocketUnitName);
  const auto service_unit =
      SystemdUserDir() / std::string(kSystemdServiceUnitName);
  const std::string socket_text =
      "[Unit]\nDescription=agent-safe-guard native daemon socket\n\n[Socket]\n"
      "ListenSequentialPacket=%t/agent-safe-guard/sgd.sock\nSocketMode=0600\n"
      "DirectoryMode=0700\nRemoveOnStop=true\n\n[Install]\nWantedBy=sockets.target\n";
  const std::string service_text =
      "[Unit]\nDescription=agent-safe-guard native daemon\n"
      "Requires=asg.socket\nAfter=asg.socket\n\n"
      "[Service]\nType=notify\nExecStart=" +
      sgd->string() +
      "\nRestart=on-failure\nRestartSec=1s\nNoNewPrivileges=true\nPrivateTmp=true\n"
      "ProtectSystem=strict\nProtectHome=read-only\nReadWritePaths=%h/.claude %t/agent-safe-guard\n";
  WriteTextFile(socket_unit, socket_text);
  WriteTextFile(service_unit, service_text);
  Info("Installed user units: asg.socket, asg.service");

  if (sg::RunProcess({"systemctl", "--user", "daemon-reload"}).exit_code == 0) {
    if (sg::RunProcess({"systemctl", "--user", "enable", "--now", "asg.socket"})
            .exit_code == 0) {
      Info("Enabled and started asg.socket");
    } else {
      Warn("Could not enable/start user socket (no user systemd session?)");
    }
  } else {
    Warn("Could not reload user systemd units (no user systemd session?)");
  }
}

void Usage() {
  std::cout
      << "Usage: asg-install [--native] [--native-bin-dir DIR] [--enable-systemd-user]\n\n"
      << "Options:\n"
      << "  --native               Native-only install; skip auto-building missing binaries.\n"
      << "  --native-bin-dir DIR   Directory containing native binaries.\n"
      << "  --enable-systemd-user  Install and enable user socket units.\n"
      << "  --no-enable-systemd-user\n"
      << "                         Skip user systemd unit install/enable.\n"
      << "  --feature-ui           Force feature selection during install.\n"
      << "  --no-feature-ui        Skip feature selection and preserve defaults.\n"
      << "  -h, --help             Show this help.\n";
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg(argv[i]);
    if (arg == "--native") {
      options.explicit_native = true;
      options.auto_build_native = false;
      continue;
    }
    if (arg == "--native-bin-dir") {
      if (i + 1 >= argc) {
        return Error("missing value for --native-bin-dir");
      }
      options.native_bin_dir = argv[++i];
      continue;
    }
    if (arg == "--enable-systemd-user") {
      options.enable_systemd_user = true;
      continue;
    }
    if (arg == "--no-enable-systemd-user") {
      options.enable_systemd_user = false;
      continue;
    }
    if (arg == "--feature-ui") {
      options.feature_ui = FeatureUiMode::kForce;
      continue;
    }
    if (arg == "--no-feature-ui") {
      options.feature_ui = FeatureUiMode::kOff;
      continue;
    }
    if (arg == "--help" || arg == "-h") {
      Usage();
      return 0;
    }
    return Error("unknown option: " + arg);
  }

  if (const char* no_autobuild = std::getenv("SG_INSTALL_NO_AUTOBUILD");
      no_autobuild != nullptr && std::string(no_autobuild) == "1") {
    options.auto_build_native = false;
  }

  if (Home().empty()) {
    return Error("HOME is not set");
  }
  if (!EnsureNativeBinaries(options)) {
    return Error("native binaries missing; build native runtime first");
  }

  std::error_code ec;
  std::filesystem::create_directories(HooksDir(), ec);
  std::filesystem::create_directories(ConfigDir(), ec);

  Info("Installing config...");
  const auto config_src = SourceRoot() / "config.env";
  const auto config_dst = ConfigDir() / "config.env";
  if (std::filesystem::exists(config_dst)) {
    Warn("  config.env already exists, skipping (" + config_src.string() +
         " has the latest defaults)");
  } else if (CopyFileIfMissing(config_src, config_dst)) {
    Info("  config.env installed (defaults)");
  } else {
    return Error("failed to install config.env");
  }
  if (!InstallDefaultFeaturesFile()) {
    return Error("failed to write features.env");
  }
  sg::EnsurePolicyStateScaffold();
  if (ShouldRunFeatureUi(options.feature_ui) && !RunFeaturePanel(options)) {
    return Error("feature selection aborted");
  }

  Info("Installing hooks...");
  const std::vector<std::string> legacy_hooks = {
      "sg-pre-tool-use",  "sg-post-tool-use",  "sg-read-guard",
      "sg-read-compress", "sg-permission-request", "sg-session-start",
      "sg-session-end",   "sg-subagent-start", "sg-subagent-stop",
      "sg-stop",          "sg-pre-compact",    "sg-tool-error"};
  for (const auto& legacy : legacy_hooks) {
    RemoveManagedHookIfPresent(HooksDir() / legacy);
  }
  std::filesystem::remove(HooksDir() / "lib/common.sh", ec);
  std::filesystem::remove(HooksDir() / "lib", ec);

  for (const auto& hook : kHooks) {
    const auto native_bin = ResolveNativeBin(options, hook.native_name);
    if (!native_bin.has_value()) {
      return Error("missing native hook binary: " + std::string(hook.native_name));
    }
    if (!InstallSymlink(HooksDir() / hook.launcher_name, *native_bin)) {
      return Error("failed to install " + std::string(hook.launcher_name));
    }
    Info("  " + std::string(hook.launcher_name) + " -> native(" +
         hook.native_name + ")");
  }

  const auto asg_cli = ResolveNativeBin(options, "asg-cli");
  const auto asg_statusline = ResolveNativeBin(options, "asg-statusline");
  const auto asg_install = ResolveNativeBin(options, "asg-install");
  const auto asg_uninstall = ResolveNativeBin(options, "asg-uninstall");
  if (!asg_cli.has_value() || !InstallSymlink(LocalBinDir() / "asg-cli", *asg_cli)) {
    return Error("failed to install asg-cli");
  }
  if (!asg_statusline.has_value() ||
      !InstallSymlink(LocalBinDir() / "asg-statusline", *asg_statusline)) {
    return Error("failed to install asg-statusline");
  }
  if (!asg_install.has_value() ||
      !InstallSymlink(LocalBinDir() / "asg-install", *asg_install)) {
    return Error("failed to install asg-install");
  }
  if (!asg_uninstall.has_value() ||
      !InstallSymlink(LocalBinDir() / "asg-uninstall", *asg_uninstall)) {
    return Error("failed to install asg-uninstall");
  }
  Info("Installed asg-cli symlink at " + (LocalBinDir() / "asg-cli").string());
  Info("Installed asg-statusline symlink at " +
       (LocalBinDir() / "asg-statusline").string());
  Info("Installed asg-install symlink at " +
       (LocalBinDir() / "asg-install").string());
  Info("Installed asg-uninstall symlink at " +
       (LocalBinDir() / "asg-uninstall").string());
#ifdef SG_HAS_REPOMAP
  const auto asg_repomap = ResolveNativeBin(options, "asg-repomap");
  if (asg_repomap.has_value()) {
    if (!InstallSymlink(LocalBinDir() / "asg-repomap", *asg_repomap)) {
      return Error("failed to install asg-repomap");
    }
    Info("Installed asg-repomap symlink at " +
         (LocalBinDir() / "asg-repomap").string());
  } else {
    Warn("asg-repomap binary missing; skipping repomap install");
  }
#endif

  Info("Merging settings.json...");
  if (!UpdateSettingsJson()) {
    return Error("failed to update settings.json");
  }

  if (options.enable_systemd_user) {
    InstallSystemdUnits(options);
  }

  std::size_t hook_count = 0;
  for (const auto& hook : kHooks) {
    if (std::filesystem::exists(HooksDir() / hook.launcher_name)) {
      ++hook_count;
    }
  }

  std::cout << "\n";
  Info("agent-safe-guard installed!");
  Info("Hooks: " + std::to_string(hook_count) + " native symlinks installed in " +
       HooksDir().string());
  Info("Config: " + (ConfigDir() / "config.env").string());
  Info("Features: " + FeaturesFile().string());
  Info("Statusline: " + (LocalBinDir() / "asg-statusline").string());
  Info("Native mode: enabled (strict, no bash fallback)");
  std::cout << "\n";
  Warn("Start a new Claude Code session to activate hooks.");
  return 0;
}
