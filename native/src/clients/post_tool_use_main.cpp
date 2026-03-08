#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/protocol.hpp"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-post-tool-use";
constexpr std::string_view kFeatureKey = "SG_FEATURE_POST_TOOL_USE";

bool IsSubagentTranscript(std::string_view transcript_path) {
  return transcript_path.find("/subagents/") != std::string_view::npos ||
         transcript_path.find("/tmp/") != std::string_view::npos;
}

bool RequiresServerSidePostToolUse(std::string_view json) {
  const std::string tool_name = sg::FindJsonString(json, "tool_name").value_or("");
  if (tool_name == "Bash" || tool_name == "Grep" || tool_name == "Glob" ||
      tool_name == "Task") {
    return true;
  }
  if (tool_name != "Read") {
    return false;
  }
  const std::string transcript_path =
      sg::FindJsonString(json, "transcript_path").value_or("");
  return IsSubagentTranscript(transcript_path);
}

void AppendContextField(std::string* json, const std::string& field_name,
                        const std::string& field_value) {
  if (json == nullptr || json->empty() || field_value.empty()) {
    return;
  }
  const auto close_pos = json->rfind('}');
  if (close_pos == std::string::npos) {
    return;
  }
  const std::string injected =
      ",\"" + field_name + "\":\"" + sg::JsonEscape(field_value) + "\"";
  json->insert(close_pos, injected);
}

std::map<std::string, std::string> LoadConfig(const std::filesystem::path& path) {
  std::map<std::string, std::string> cfg;
  std::ifstream in(path);
  if (!in) {
    return cfg;
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

    const auto trim = [](const std::string& s) {
      std::size_t first = 0;
      while (first < s.size() && std::isspace(static_cast<unsigned char>(s[first])) != 0) {
        ++first;
      }
      std::size_t last = s.size();
      while (last > first && std::isspace(static_cast<unsigned char>(s[last - 1])) != 0) {
        --last;
      }
      return s.substr(first, last - first);
    };

    const std::string key = trim(line.substr(0, eq_pos));
    const std::string value = trim(line.substr(eq_pos + 1));
    if (!key.empty() && !value.empty()) {
      cfg[key] = value;
    }
  }

  return cfg;
}

std::string WithContext(std::string input_json) {
  const std::string home = std::getenv("HOME") != nullptr ? std::getenv("HOME") : "";

  const std::string state_dir =
      std::getenv("SG_STATE_DIR") != nullptr ? std::getenv("SG_STATE_DIR") : "";
  const std::string subagent_state_dir = std::getenv("SG_SUBAGENT_STATE_DIR") != nullptr
                                             ? std::getenv("SG_SUBAGENT_STATE_DIR")
                                             : "";
  const std::string events_file =
      std::getenv("SG_EVENTS_FILE") != nullptr ? std::getenv("SG_EVENTS_FILE") : "";

  AppendContextField(&input_json, "sg_state_dir", state_dir);
  AppendContextField(&input_json, "sg_subagent_state_dir", subagent_state_dir);
  AppendContextField(&input_json, "sg_events_file", events_file);

  if (!home.empty()) {
    const std::filesystem::path config_path =
        std::filesystem::path(home) / ".claude/.safeguard/config.env";
    const auto cfg = LoadConfig(config_path);
    auto add_cfg = [&](const char* key, const char* field) {
      const auto it = cfg.find(key);
      if (it != cfg.end()) {
        AppendContextField(&input_json, field, it->second);
      }
    };
    add_cfg("SG_TRUNCATE_BYTES", "sg_truncate_bytes");
    add_cfg("SG_SUBAGENT_READ_BYTES", "sg_subagent_read_bytes");
    add_cfg("SG_SUPPRESS_BYTES", "sg_suppress_bytes");
    add_cfg("SG_BUDGET_TOTAL", "sg_budget_total");

    const std::filesystem::path budget_state =
        std::filesystem::path(home) / ".claude/.safeguard/budget.state";
    AppendContextField(&input_json, "sg_budget_state_file", budget_state.string());
  }

  return input_json;
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
  const bool requires_server_side = RequiresServerSidePostToolUse(input);

  if (input.size() > sg::kMaxProtocolPayloadBytes && !requires_server_side) {
    sg::DebugLog(kClientName,
                 "oversize PostToolUse payload bypassed for passthrough tool");
    sg::EmitPassthrough();
    return 0;
  }

  std::string error;
  sg::ResponseFrame response;
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kPostToolUse, input, &response,
                           &error)) {
    if (!requires_server_side) {
      sg::DebugLog(kClientName,
                   error.empty()
                       ? "native exchange failed; bypassing passthrough tool"
                       : "native exchange failed for passthrough tool: " + error);
      sg::EmitPassthrough();
      return 0;
    }
    return sg::FailClosed(kClientName, error.empty()
                                           ? "native exchange failed"
                                           : error);
  }

  if (response.status != sg::Status::kOk) {
    return sg::FailClosed(kClientName, "daemon returned non-ok status");
  }

  std::cout << response.payload;
  return 0;
}
