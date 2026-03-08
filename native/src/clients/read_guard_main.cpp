#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/protocol.hpp"

#include <charconv>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-read-guard";
constexpr std::string_view kFeatureKey = "SG_FEATURE_READ_GUARD";

void AppendContextField(std::string* json, std::string_view field_name,
                        std::string_view field_value) {
  if (json == nullptr || json->empty() || field_value.empty()) {
    return;
  }
  const auto close_pos = json->rfind('}');
  if (close_pos == std::string::npos) {
    return;
  }

  const std::string injected =
      ",\"" + std::string(field_name) + "\":\"" + sg::JsonEscape(field_value) +
      "\"";
  json->insert(close_pos, injected);
}

std::map<std::string, std::string> LoadConfig(const std::filesystem::path& path) {
  std::map<std::string, std::string> cfg;
  std::ifstream in(path);
  if (!in) {
    return cfg;
  }

  const auto trim = [](const std::string& s) {
    std::size_t first = 0;
    while (first < s.size() &&
           std::isspace(static_cast<unsigned char>(s[first])) != 0) {
      ++first;
    }
    std::size_t last = s.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(s[last - 1])) != 0) {
      --last;
    }
    return s.substr(first, last - first);
  };

  for (std::string line; std::getline(in, line);) {
    const auto comment_pos = line.find('#');
    if (comment_pos != std::string::npos) {
      line = line.substr(0, comment_pos);
    }
    const auto eq_pos = line.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }

    const std::string key = trim(line.substr(0, eq_pos));
    const std::string value = trim(line.substr(eq_pos + 1));
    if (!key.empty() && !value.empty()) {
      cfg[key] = value;
    }
  }
  return cfg;
}

std::string WithContext(std::string input_json) {
  std::string configured_max_mb;
  if (const char* env = std::getenv("SG_READ_GUARD_MAX_MB");
      env != nullptr && *env != '\0') {
    configured_max_mb = env;
  }

  if (configured_max_mb.empty()) {
    const char* home = std::getenv("HOME");
    if (home != nullptr && *home != '\0') {
      const std::filesystem::path config_path =
          std::filesystem::path(home) / ".claude/.safeguard/config.env";
      const auto cfg = LoadConfig(config_path);
      const auto it = cfg.find("SG_READ_GUARD_MAX_MB");
      if (it != cfg.end()) {
        configured_max_mb = it->second;
      }
    }
  }

  AppendContextField(&input_json, "sg_read_guard_max_mb", configured_max_mb);
  return input_json;
}

void AppendReadGuardEvent(const std::string& input_json,
                          const std::string& response_payload) {
  const std::string decision =
      sg::FindJsonString(response_payload, "decision").value_or("");
  if (decision.empty()) {
    return;
  }

  const std::string session_id =
      sg::FindJsonString(input_json, "session_id").value_or("");
  const std::string file_path =
      sg::FindJsonString(input_json, "file_path").value_or("");
  const std::string message =
      sg::FindJsonString(response_payload, "message").value_or("");

  std::ostringstream event;
  event << "{\"event_type\":\"read_guard\",\"timestamp\":" << sg::UnixNow()
        << ",\"decision\":\"" << sg::JsonEscape(decision) << "\"";
  if (!session_id.empty()) {
    event << ",\"session_id\":\"" << sg::JsonEscape(session_id) << "\"";
  }
  if (!file_path.empty()) {
    event << ",\"file_path\":\"" << sg::JsonEscape(file_path) << "\"";
  }
  if (!message.empty()) {
    event << ",\"message\":\"" << sg::JsonEscape(message) << "\"";
  }
  event << ",\"hook\":\"read_guard\"}";
  sg::AppendEventLine(sg::DefaultEventsFilePath(), event.str());
}

int ParseExitCode(std::string_view raw) {
  if (raw.empty()) {
    return 2;
  }
  int value = 2;
  const auto [ptr, ec] = std::from_chars(raw.data(), raw.data() + raw.size(), value);
  if (ec != std::errc() || ptr != raw.data() + raw.size()) {
    return 2;
  }
  return value;
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_path = sg::DefaultSocketPath();
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--socket") {
      if (i + 1 >= argc) {
        return sg::FailClosed(kClientName, "missing --socket value");
      }
      socket_path = argv[++i];
      continue;
    }
    if (arg == "--help" || arg == "-h") {
      std::cerr << "Usage: " << argv[0] << " [--socket PATH]\n";
      return 0;
    }
  }

  if (!sg::IsFeatureEnabled(kFeatureKey)) {
    sg::EmitPassthrough();
    return 0;
  }

  std::string input = sg::ReadAllStdin();
  input = WithContext(std::move(input));

  std::string error;
  sg::ResponseFrame response;
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kReadGuard, input, &response,
                           &error)) {
    return sg::FailClosed(kClientName, error.empty()
                                           ? "native exchange failed"
                                           : error);
  }

  if (response.status != sg::Status::kOk) {
    return sg::FailClosed(kClientName, "daemon returned non-ok status");
  }

  AppendReadGuardEvent(input, response.payload);
  const std::string decision =
      sg::FindJsonString(response.payload, "decision").value_or("allow");
  if (decision != "deny") {
    return 0;
  }

  const std::string message =
      sg::FindJsonString(response.payload, "message").value_or("");
  if (!message.empty()) {
    std::cerr << message << "\n";
  }

  return ParseExitCode(
      sg::FindJsonString(response.payload, "exit_code").value_or("2"));
}
