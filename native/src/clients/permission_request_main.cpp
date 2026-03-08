#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/protocol.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-permission-request";
constexpr std::string_view kFeatureKey = "SG_FEATURE_PERMISSION_REQUEST";

void AppendPermissionDecisionEvent(const std::string& input_json,
                                   const std::string& response_payload) {
  std::string decision =
      sg::FindJsonString(response_payload, "behavior").value_or("");
  if (decision.empty()) {
    if (response_payload.find("\"suppressOutput\":true") ==
        std::string::npos) {
      return;
    }
    decision = "suppress";
  }

  const std::string command =
      sg::FindJsonString(input_json, "command").value_or("");
  const std::string session_id =
      sg::FindJsonString(input_json, "session_id").value_or("");
  const std::string message =
      sg::FindJsonString(response_payload, "message").value_or("");

  std::ostringstream event;
  event << "{\"event_type\":\"permission_decision\",\"timestamp\":"
        << sg::UnixNow() << ",\"decision\":\"" << sg::JsonEscape(decision)
        << "\"";
  if (!session_id.empty()) {
    event << ",\"session_id\":\"" << sg::JsonEscape(session_id) << "\"";
  }
  if (!command.empty()) {
    event << ",\"command\":\"" << sg::JsonEscape(command) << "\"";
  }
  if (!message.empty()) {
    event << ",\"message\":\"" << sg::JsonEscape(message) << "\"";
  }
  event << ",\"hook\":\"permission_request\"}";
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

  std::string error;
  sg::ResponseFrame response;
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kPermissionRequest, input,
                           &response, &error)) {
    return sg::FailClosed(kClientName, error.empty()
                                           ? "native exchange failed"
                                           : error);
  }

  if (response.status != sg::Status::kOk) {
    return sg::FailClosed(kClientName, "daemon returned non-ok status");
  }

  AppendPermissionDecisionEvent(input, response.payload);
  std::cout << response.payload;
  return 0;
}
