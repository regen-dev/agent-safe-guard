#include "sg/client_runtime.hpp"
#include "sg/protocol.hpp"
#include "sg/json_extract.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-pre-tool-use";
constexpr std::string_view kFeatureKey = "SG_FEATURE_PRE_TOOL_USE";

void AppendContextField(std::string* json, const char* env_name,
                        const char* field_name) {
  sg::AppendEnvJsonField(json, env_name, field_name);
}

std::string WithContext(std::string input_json) {
  AppendContextField(&input_json, "SG_SUBAGENT_STATE_DIR", "sg_subagent_state_dir");
  AppendContextField(&input_json, "SG_DEFAULT_CALL_LIMIT", "sg_default_call_limit");
  AppendContextField(&input_json, "SG_DEFAULT_BYTE_LIMIT", "sg_default_byte_limit");
  return input_json;
}

void AppendBlockedEvent(const std::string& input_json,
                        const std::string& response_payload) {
  if (sg::FindJsonString(response_payload, "permissionDecision").value_or("") !=
      "deny") {
    return;
  }

  const std::string session_id =
      sg::FindJsonString(input_json, "session_id").value_or("");
  const std::string tool_name =
      sg::FindJsonString(input_json, "tool_name").value_or("");
  const std::string command =
      sg::FindJsonString(input_json, "command").value_or("");
  const std::string reason = sg::FindJsonString(response_payload,
                                                "permissionDecisionReason")
                                 .value_or("");

  std::ostringstream event;
  event << "{\"event_type\":\"blocked\",\"timestamp\":" << sg::UnixNow();
  if (!session_id.empty()) {
    event << ",\"session_id\":\"" << sg::JsonEscape(session_id) << "\"";
  }
  if (!tool_name.empty()) {
    event << ",\"tool\":\"" << sg::JsonEscape(tool_name) << "\"";
  }
  if (!command.empty()) {
    event << ",\"command\":\"" << sg::JsonEscape(command) << "\"";
  }
  if (!reason.empty()) {
    event << ",\"reason\":\"" << sg::JsonEscape(reason) << "\"";
  }
  event << ",\"hook\":\"pre_tool_use\"}";
  sg::AppendEventLine(sg::DefaultEventsFilePath(), event.str());
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
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kPreToolUse, input, &response,
                           &error)) {
    return sg::FailClosed(kClientName, error.empty()
                                           ? "native exchange failed"
                                           : error);
  }
  if (response.status != sg::Status::kOk) {
    return sg::FailClosed(kClientName, "daemon returned non-ok status");
  }

  AppendBlockedEvent(input, response.payload);
  std::cout << response.payload;
  return 0;
}
