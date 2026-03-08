#include "sg/process.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace {

constexpr std::string_view kSystemdSocketUnitName = "asg.socket";
constexpr std::string_view kSystemdServiceUnitName = "asg.service";
constexpr std::string_view kLegacySystemdSocketUnitName =
    "agent-safe-guard-sgd.socket";
constexpr std::string_view kLegacySystemdServiceUnitName =
    "agent-safe-guard-sgd.service";

std::string Green() { return "\033[32m"; }
std::string Yellow() { return "\033[33m"; }
std::string Reset() { return "\033[0m"; }

void Info(const std::string& text) {
  std::cout << Green() << "[-]" << Reset() << " " << text << "\n";
}

void Warn(const std::string& text) {
  std::cout << Yellow() << "[!]" << Reset() << " " << text << "\n";
}

std::string Home() {
  const char* home = std::getenv("HOME");
  return home != nullptr ? std::string(home) : std::string();
}

std::filesystem::path ClaudeDir() {
  return std::filesystem::path(Home()) / ".claude";
}

std::filesystem::path HooksDir() {
  return ClaudeDir() / "hooks";
}

std::filesystem::path SettingsFile() {
  return ClaudeDir() / "settings.json";
}

std::filesystem::path LocalBinDir() {
  return std::filesystem::path(Home()) / ".local/bin";
}

std::filesystem::path SystemdUserDir() {
  return std::filesystem::path(Home()) / ".config/systemd/user";
}

void Usage() {
  std::cout << "Usage: asg-uninstall\n\n"
            << "Removes installed agent-safe-guard hook symlinks, local launchers,\n"
            << "managed status line wiring, and optional user systemd units.\n"
            << "Config and local state under ~/.claude/.safeguard and\n"
            << "~/.claude/.statusline are preserved.\n\n"
            << "Options:\n"
            << "  -h, --help             Show this help.\n";
}

bool WriteTextFile(const std::filesystem::path& path, const std::string& text) {
  std::ofstream out(path, std::ios::trunc | std::ios::binary);
  if (!out) {
    return false;
  }
  out << text;
  return static_cast<bool>(out);
}

void RemoveHookIfInstalled(const std::filesystem::path& path) {
  std::error_code ec;
  if (std::filesystem::is_symlink(path, ec) || std::filesystem::is_regular_file(path, ec)) {
    std::filesystem::remove(path, ec);
    Info("  Removed " + path.filename().string());
  }
}

void CleanupSystemdUnits() {
  std::error_code ec;
  const auto current_socket = SystemdUserDir() / std::string(kSystemdSocketUnitName);
  const auto current_service = SystemdUserDir() / std::string(kSystemdServiceUnitName);
  const auto legacy_socket =
      SystemdUserDir() / std::string(kLegacySystemdSocketUnitName);
  const auto legacy_service =
      SystemdUserDir() / std::string(kLegacySystemdServiceUnitName);

  const bool has_current = std::filesystem::exists(current_socket, ec) ||
                           std::filesystem::exists(current_service, ec);
  ec.clear();
  const bool has_legacy = std::filesystem::exists(legacy_socket, ec) ||
                          std::filesystem::exists(legacy_service, ec);
  if (!has_current && !has_legacy) {
    return;
  }

  Info("Cleaning user systemd units...");
  sg::RunProcess(
      {"systemctl", "--user", "disable", "--now", std::string(kSystemdSocketUnitName)});
  sg::RunProcess(
      {"systemctl", "--user", "disable", "--now", std::string(kSystemdServiceUnitName)});
  sg::RunProcess({"systemctl", "--user", "disable", "--now",
                  std::string(kLegacySystemdSocketUnitName)});
  sg::RunProcess({"systemctl", "--user", "disable", "--now",
                  std::string(kLegacySystemdServiceUnitName)});

  std::filesystem::remove(current_socket, ec);
  std::filesystem::remove(current_service, ec);
  std::filesystem::remove(legacy_socket, ec);
  std::filesystem::remove(legacy_service, ec);
  std::filesystem::remove(SystemdUserDir(), ec);
  sg::RunProcess({"systemctl", "--user", "daemon-reload"});
}

bool CleanupSettings() {
  const auto settings = SettingsFile();
  if (!std::filesystem::exists(settings)) {
    return true;
  }
  const auto validate = sg::RunProcess({"jq", "empty", settings.string()});
  if (validate.exit_code != 0) {
    return true;
  }
  const std::string filter = R"JQ(
      if .hooks then
        .hooks |= with_entries(
          .value |= map(select(
            (.hooks // []) | all(.command | (test("asg-") or test("sg-")) | not)
          ))
          | if .value | length == 0 then .value = [] else . end
        )
        | .hooks |= with_entries(select(.value | length > 0))
      else . end
      | if (.statusLine.command == "~/.local/bin/asg-statusline" or .statusLine.command == "~/.claude/statusline.sh")
          then del(.statusLine)
          else .
        end
  )JQ";
  const auto cleaned = sg::RunProcess({"jq", filter, settings.string()});
  if (cleaned.exit_code != 0) {
    return false;
  }
  const auto tmp = settings.string() + ".tmp";
  if (!WriteTextFile(tmp, cleaned.stdout_text)) {
    return false;
  }
  const auto revalidate = sg::RunProcess({"jq", "empty", tmp});
  if (revalidate.exit_code != 0) {
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
  Info("  settings.json cleaned");
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg(argv[i]);
    if (arg == "--help" || arg == "-h") {
      Usage();
      return 0;
    }
    std::cerr << "unknown option: " << arg << "\n";
    return 1;
  }

  if (Home().empty()) {
    std::cerr << "HOME is not set\n";
    return 1;
  }

  Info("Removing installed hooks...");
  const std::vector<std::string> hooks = {
      "asg-pre-tool-use",  "asg-post-tool-use",  "asg-read-guard",
      "asg-read-compress", "asg-permission-request",
      "asg-session-start", "asg-session-end", "asg-subagent-start",
      "asg-subagent-stop", "asg-stop", "asg-pre-compact", "asg-tool-error",
      "sg-pre-tool-use",   "sg-post-tool-use",   "sg-read-guard",
      "sg-read-compress",  "sg-permission-request",
      "sg-session-start",  "sg-session-end",     "sg-subagent-start",
      "sg-subagent-stop",  "sg-stop",            "sg-pre-compact",
      "sg-tool-error"};
  for (const auto& hook : hooks) {
    RemoveHookIfInstalled(HooksDir() / hook);
  }

  RemoveHookIfInstalled(LocalBinDir() / "asg-cli");
  RemoveHookIfInstalled(LocalBinDir() / "asg-statusline");
  RemoveHookIfInstalled(LocalBinDir() / "asg-install");
  RemoveHookIfInstalled(LocalBinDir() / "asg-uninstall");
  std::error_code ec;
  std::filesystem::remove(ClaudeDir() / "statusline.sh", ec);

  CleanupSystemdUnits();

  if (!CleanupSettings()) {
    Warn("  Failed to clean settings.json");
  }

  std::cout << "\n";
  Info("agent-safe-guard uninstalled.");
  Warn("Config preserved at: " + (ClaudeDir() / ".safeguard").string());
  Warn("State preserved at: " + (ClaudeDir() / ".statusline").string());
  return 0;
}
