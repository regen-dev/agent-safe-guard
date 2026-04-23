#include "sg/client_runtime.hpp"

#include "sg/json_extract.hpp"
#include "sg/transport.hpp"

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <sys/stat.h>
#include <sstream>
#include <string>
#include <system_error>
#include <unistd.h>
#include <vector>

namespace sg {
namespace {

constexpr std::uintmax_t kLocalAuditCapBytes =
    1024ull * 1024ull * 1024ull;

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

std::filesystem::path DefaultFeaturesFilePath() {
  if (const char* explicit_path = std::getenv("SG_FEATURES_FILE");
      explicit_path != nullptr && *explicit_path != '\0') {
    return explicit_path;
  }
  if (const char* home = std::getenv("HOME");
      home != nullptr && *home != '\0') {
    return std::filesystem::path(home) / ".claude/.safeguard/features.env";
  }
  return {};
}

bool ParseFeatureValue(std::string_view value, bool fallback) {
  std::string lowered = Trim(value);
  for (char& ch : lowered) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }

  if (lowered == "1" || lowered == "true" || lowered == "yes" ||
      lowered == "on" || lowered == "y") {
    return true;
  }
  if (lowered == "0" || lowered == "false" || lowered == "no" ||
      lowered == "off" || lowered == "n") {
    return false;
  }
  return fallback;
}

bool TelemetryEndpointConfigured() {
  const char* raw = std::getenv("SG_TELEMETRY_ENDPOINT");
  return raw != nullptr && *raw != '\0';
}

std::string RuntimeSocketPath(std::string_view runtime_dir) {
  if (runtime_dir.empty()) {
    return "";
  }
  return std::string(runtime_dir) + "/agent-safe-guard/sgd.sock";
}

std::string RunUserSocketPath() {
  const uid_t uid = ::getuid();
  return "/run/user/" + std::to_string(static_cast<unsigned long>(uid)) +
         "/agent-safe-guard/sgd.sock";
}

bool SocketExists(const std::string& path) {
  if (path.empty()) {
    return false;
  }
  struct stat st {};
  return ::lstat(path.c_str(), &st) == 0 && S_ISSOCK(st.st_mode);
}

}  // namespace

std::string DefaultSocketPath() {
  if (const char* env_path = std::getenv("SG_DAEMON_SOCKET");
      env_path != nullptr && *env_path != '\0') {
    return env_path;
  }
  if (const char* runtime = std::getenv("XDG_RUNTIME_DIR");
      runtime != nullptr && *runtime != '\0') {
    const std::string runtime_socket = RuntimeSocketPath(runtime);
    if (SocketExists(runtime_socket)) {
      return runtime_socket;
    }
  }
  const std::string run_user_socket = RunUserSocketPath();
  if (SocketExists(run_user_socket)) {
    return run_user_socket;
  }
  if (SocketExists("/tmp/agent-safe-guard/sgd.sock")) {
    return "/tmp/agent-safe-guard/sgd.sock";
  }
  if (const char* runtime = std::getenv("XDG_RUNTIME_DIR");
      runtime != nullptr && *runtime != '\0') {
    return RuntimeSocketPath(runtime);
  }
  return "/tmp/agent-safe-guard/sgd.sock";
}

bool DebugEnabled() {
  const char* raw = std::getenv("SG_NATIVE_DEBUG");
  return raw != nullptr && *raw != '\0' && std::string_view(raw) != "0";
}

void DebugLog(std::string_view client_name, std::string_view message) {
  if (DebugEnabled()) {
    std::cerr << client_name << ": " << message << "\n";
  }
}

int FailClosed(std::string_view client_name, const std::string& reason) {
  DebugLog(client_name, reason);
  std::cout << kClientFailClosedResponse;
  return 0;
}

std::optional<std::string> ReadFeatureSetting(std::string_view feature_key) {
  if (feature_key.empty()) {
    return std::nullopt;
  }

  // Environment variable takes precedence over the features.env file.
  // This lets test setups disable specific features cleanly via
  // `export SG_FEATURE_XXX=0` without clobbering the installer-managed
  // defaults file.
  {
    const std::string key(feature_key);
    if (const char* env = std::getenv(key.c_str());
        env != nullptr && *env != '\0') {
      return std::string(env);
    }
  }

  const auto features_path = DefaultFeaturesFilePath();
  if (features_path.empty()) {
    return std::nullopt;
  }

  std::ifstream in(features_path);
  if (!in) {
    return std::nullopt;
  }

  for (std::string line; std::getline(in, line);) {
    const auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }
    const auto eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }

    const std::string key = Trim(line.substr(0, eq_pos));
    if (key != feature_key) {
      continue;
    }
    return Trim(line.substr(eq_pos + 1));
  }

  return std::nullopt;
}

bool IsFeatureEnabled(std::string_view feature_key) {
  if (feature_key.empty()) {
    return true;
  }

  const auto raw = ReadFeatureSetting(feature_key);
  if (!raw.has_value()) {
    return true;
  }
  return ParseFeatureValue(*raw, true);
}

void EmitPassthrough() { std::cout << kClientPassthroughResponse; }

std::string ReadAllStdin() {
  return std::string((std::istreambuf_iterator<char>(std::cin)),
                     std::istreambuf_iterator<char>());
}

bool ExchangeRequest(std::string_view socket_path, Hook hook, std::string payload,
                     ResponseFrame* response, std::string* error) {
  if (response == nullptr || error == nullptr) {
    return false;
  }

  RequestFrame request;
  request.hook = hook;
  request.payload = std::move(payload);
  const auto encoded_request = EncodeRequest(request);

  const int fd = ConnectClient(std::string(socket_path), error);
  if (fd < 0) {
    return false;
  }

  if (!SendPacket(fd, encoded_request, error)) {
    CloseFd(fd);
    return false;
  }

  std::vector<std::uint8_t> packet;
  if (!RecvPacket(fd, &packet, error)) {
    CloseFd(fd);
    return false;
  }

  CloseFd(fd);
  return DecodeResponse(packet, response, error);
}

void AppendEnvJsonField(std::string* json, const char* env_name,
                        const char* field_name) {
  if (json == nullptr || json->empty()) {
    return;
  }
  const char* raw = std::getenv(env_name);
  if (raw == nullptr || *raw == '\0') {
    return;
  }
  const auto close_pos = json->rfind('}');
  if (close_pos == std::string::npos) {
    return;
  }
  const std::string injected =
      ",\"" + std::string(field_name) + "\":\"" + JsonEscape(raw) + "\"";
  json->insert(close_pos, injected);
}

std::filesystem::path DefaultEventsFilePath() {
  if (const char* explicit_path = std::getenv("SG_EVENTS_FILE");
      explicit_path != nullptr && *explicit_path != '\0') {
    return explicit_path;
  }
  if (const char* home = std::getenv("HOME");
      home != nullptr && *home != '\0') {
    return std::filesystem::path(home) / ".claude/.statusline/events.jsonl";
  }
  return "/tmp/.sg-events.jsonl";
}

void AppendEventLine(const std::filesystem::path& path,
                     std::string_view json_line) {
  std::error_code ec;
  if (!path.has_parent_path()) {
    return;
  }
  std::filesystem::create_directories(path.parent_path(), ec);
  if (!TelemetryEndpointConfigured()) {
    const std::uintmax_t current_size =
        std::filesystem::exists(path, ec) && !ec
            ? std::filesystem::file_size(path, ec)
            : 0;
    if (!ec) {
      const std::uintmax_t line_size =
          static_cast<std::uintmax_t>(json_line.size()) + 1ull;
      if (current_size >= kLocalAuditCapBytes ||
          current_size + line_size > kLocalAuditCapBytes) {
        return;
      }
    }
  }
  std::ofstream out(path, std::ios::app);
  if (!out) {
    return;
  }
  out << json_line << '\n';
}

long UnixNow() {
  return static_cast<long>(std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now()));
}

}  // namespace sg
