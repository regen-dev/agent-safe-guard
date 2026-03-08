#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/protocol.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-subagent-start";
constexpr std::string_view kFeatureKey = "SG_FEATURE_SUBAGENT_START";

void AppendContextField(std::string* json, const char* env_name,
                        const char* field_name) {
  sg::AppendEnvJsonField(json, env_name, field_name);
}

std::string WithContext(std::string input_json) {
  AppendContextField(&input_json, "HOME", "sg_home");
  AppendContextField(&input_json, "SG_STATE_DIR", "sg_state_dir");
  AppendContextField(&input_json, "SG_EVENTS_FILE", "sg_events_file");
  AppendContextField(&input_json, "SG_SUBAGENT_STATE_DIR", "sg_subagent_state_dir");
  AppendContextField(&input_json, "SG_BUDGET_TOTAL", "sg_budget_total");
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

  std::string error;
  sg::ResponseFrame response;
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kSubagentStart, input,
                           &response, &error)) {
    return sg::FailClosed(kClientName, error.empty()
                                           ? "native exchange failed"
                                           : error);
  }

  if (response.status != sg::Status::kOk) {
    return sg::FailClosed(kClientName, "daemon returned non-ok status");
  }

  if (!response.payload.empty()) {
    std::cout << response.payload;
  }
  return 0;
}
