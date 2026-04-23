#include "sg/client_runtime.hpp"
#include "sg/json_extract.hpp"
#include "sg/protocol.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-session-start";
constexpr std::string_view kFeatureKey = "SG_FEATURE_SESSION_START";
constexpr std::string_view kRepomapFeatureKey = "SG_FEATURE_REPOMAP";

void AppendContextField(std::string* json, const char* env_name,
                        const char* field_name) {
  sg::AppendEnvJsonField(json, env_name, field_name);
}

std::string WithContext(std::string input_json) {
  AppendContextField(&input_json, "HOME", "sg_home");
  AppendContextField(&input_json, "SG_STATE_DIR", "sg_state_dir");
  AppendContextField(&input_json, "SG_EVENTS_FILE", "sg_events_file");
  AppendContextField(&input_json, "SG_SESSION_BUDGET_DIR", "sg_session_budget_dir");
  AppendContextField(&input_json, "SG_BUDGET_TOTAL", "sg_budget_total");
  AppendContextField(&input_json, "PWD", "sg_pwd");
  return input_json;
}

std::string BuildRepomapRequest() {
  const char* pwd_raw = std::getenv("PWD");
  const std::string pwd = (pwd_raw != nullptr) ? std::string(pwd_raw) : "";
  const char* budget_env = std::getenv("SG_REPOMAP_MAX_TOKENS");
  const std::string budget_str = (budget_env != nullptr && *budget_env != '\0')
                                     ? std::string(budget_env)
                                     : std::string("4096");
  std::string out;
  out.reserve(pwd.size() + 48);
  out.append("{\"cwd\":\"");
  out.append(sg::JsonEscape(pwd));
  out.append("\",\"budget\":");
  out.append(budget_str);
  out.append("}");
  return out;
}

// If session-start's response already forces a decision (deny / continue=false),
// don't override with additionalContext.
bool ResponseIsDecisive(std::string_view payload) {
  if (payload.find("\"continue\":false") != std::string_view::npos) return true;
  if (payload.find("\"decision\":\"deny\"") != std::string_view::npos) return true;
  return false;
}

std::string BuildAdditionalContextOutput(std::string_view repomap_text) {
  std::string out;
  out.reserve(repomap_text.size() + 96);
  out.append(
      "{\"hookSpecificOutput\":{\"hookEventName\":\"SessionStart\","
      "\"additionalContext\":\"");
  out.append(sg::JsonEscape(repomap_text));
  out.append("\"}}");
  return out;
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
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kSessionStart, input,
                           &response, &error)) {
    return sg::FailClosed(kClientName, error.empty()
                                           ? "native exchange failed"
                                           : error);
  }

  if (response.status != sg::Status::kOk) {
    return sg::FailClosed(kClientName, "daemon returned non-ok status");
  }

  const std::string session_payload = response.payload;

  // Attempt repomap render if the feature is enabled AND session-start didn't
  // already dictate a decision.
  if (sg::IsFeatureEnabled(kRepomapFeatureKey) &&
      !ResponseIsDecisive(session_payload)) {
    sg::ResponseFrame rm_response;
    std::string rm_error;
    const std::string rm_request = BuildRepomapRequest();
    if (sg::ExchangeRequest(socket_path, sg::Hook::kRepomapRender, rm_request,
                            &rm_response, &rm_error) &&
        rm_response.status == sg::Status::kOk) {
      const auto ok_opt = sg::FindJsonString(rm_response.payload, "ok");
      const bool ok_flag =
          rm_response.payload.find("\"ok\":true") != std::string::npos;
      const auto text = sg::FindJsonString(rm_response.payload, "text");
      if (ok_flag && text.has_value() && !text->empty()) {
        std::cout << BuildAdditionalContextOutput(*text);
        return 0;
      }
      (void)ok_opt;
    } else {
      sg::DebugLog(kClientName,
                   rm_error.empty() ? "repomap exchange failed" : rm_error);
    }
    // Fall through to the session-start payload below.
  }

  if (!session_payload.empty()) {
    std::cout << session_payload;
  }
  return 0;
}
