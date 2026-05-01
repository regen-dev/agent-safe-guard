#include "sg/catalog_rule_compiler.hpp"
#include "sg/json_extract.hpp"
#include "sg/policy_catalog.hpp"
#include "sg/policy_post_tool_use.hpp"
#include "sg/policy_pre_tool_use.hpp"
#include "sg/policy_pre_compact.hpp"
#include "sg/policy_permission_request.hpp"
#include "sg/policy_read_compress.hpp"
#include "sg/policy_read_guard.hpp"
#include "sg/policy_secrets.hpp"
#include "sg/policy_session_end.hpp"
#include "sg/policy_session_start.hpp"
#include "sg/policy_stop.hpp"
#include "sg/policy_subagent_start.hpp"
#include "sg/policy_subagent_stop.hpp"
#include "sg/policy_tool_error.hpp"
#ifdef SG_HAS_REPOMAP
#include "sg/policy_repomap.hpp"
#endif
#include "sg/protocol.hpp"
#include "sg/rss_watchdog.hpp"
#include "sg/systemd_notify.hpp"
#include "sg/transport.hpp"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <poll.h>

namespace {

std::atomic<bool> g_running{true};

void SignalHandler(int) { g_running.store(false); }

std::string DefaultSocketPath() {
  if (const char* env_path = std::getenv("SG_DAEMON_SOCKET");
      env_path != nullptr && *env_path != '\0') {
    return env_path;
  }
  if (const char* runtime = std::getenv("XDG_RUNTIME_DIR");
      runtime != nullptr && *runtime != '\0') {
    return std::string(runtime) + "/agent-safe-guard/sgd.sock";
  }
  return "/tmp/agent-safe-guard/sgd.sock";
}

void PrintUsage(const char* argv0) {
  std::cerr << "Usage: " << argv0 << " [--socket PATH] [--once]\n";
}

const char* HookLabel(sg::Hook hook) {
  switch (hook) {
    case sg::Hook::kPreToolUse:        return "pre_tool_use";
    case sg::Hook::kPostToolUse:       return "post_tool_use";
    case sg::Hook::kPermissionRequest: return "permission_request";
    case sg::Hook::kReadGuard:         return "read_guard";
    case sg::Hook::kReadCompress:      return "read_compress";
    case sg::Hook::kStop:              return "stop";
    case sg::Hook::kSessionStart:      return "session_start";
    case sg::Hook::kSessionEnd:        return "session_end";
    case sg::Hook::kPreCompact:        return "pre_compact";
    case sg::Hook::kSubagentStart:     return "subagent_start";
    case sg::Hook::kSubagentStop:      return "subagent_stop";
    case sg::Hook::kToolError:         return "tool_error";
    case sg::Hook::kRepomapRender:     return "repomap_render";
    default:                           return "unknown";
  }
}

// Log to journal when a request is blocked/denied.
void LogIfBlocked(sg::Hook hook, std::string_view request_payload,
                  std::string_view response_payload) {
  if (response_payload.empty()) {
    return;
  }

  // Detect deny across all response formats.
  const bool has_deny =
      response_payload.find("\"deny\"") != std::string_view::npos;
  if (!has_deny) {
    return;
  }

  const std::string tool =
      sg::FindJsonString(request_payload, "tool_name").value_or("?");

  // Extract reason from whichever format matched.
  std::string reason;
  // Format 1: {"decision":"deny","message":"..."}
  auto msg = sg::FindJsonString(response_payload, "message");
  if (msg.has_value() && !msg->empty()) {
    reason = std::move(*msg);
  }
  // Format 2: {"...":"permissionDecisionReason":"..."}
  if (reason.empty()) {
    auto r = sg::FindJsonString(response_payload, "permissionDecisionReason");
    if (r.has_value() && !r->empty()) {
      reason = std::move(*r);
    }
  }
  if (reason.empty()) {
    reason = "(no reason)";
  }

  std::cerr << "sgd: BLOCKED [" << HookLabel(hook) << "] tool=" << tool
            << " | " << reason << "\n";
}

sg::ResponseFrame HandleRequest(const sg::RequestFrame& request) {
  sg::ResponseFrame response;
  response.status = sg::Status::kOk;

  switch (request.hook) {
    case sg::Hook::kPreToolUse:
      response.payload = sg::EvaluatePreToolUse(request.payload);
      break;
    case sg::Hook::kPostToolUse:
      response.payload = sg::EvaluatePostToolUse(request.payload);
      break;
    case sg::Hook::kPermissionRequest:
      response.payload = sg::EvaluatePermissionRequest(request.payload);
      break;
    case sg::Hook::kReadGuard: {
      // Secrets defense runs first; if it denies, skip default read guard.
      const std::string secrets_result =
          sg::EvaluateSecretsReadGuard(request.payload);
      response.payload = secrets_result.empty()
                             ? sg::EvaluateReadGuard(request.payload)
                             : secrets_result;
      break;
    }
    case sg::Hook::kReadCompress: {
      // Secrets defense runs first; if it masks .env, skip default compress.
      const std::string secrets_result =
          sg::EvaluateSecretsReadCompress(request.payload);
      response.payload = secrets_result.empty()
                             ? sg::EvaluateReadCompress(request.payload)
                             : secrets_result;
      break;
    }
    case sg::Hook::kStop:
      response.payload = sg::EvaluateStop(request.payload);
      break;
    case sg::Hook::kSessionStart:
      response.payload = sg::EvaluateSessionStart(request.payload);
      break;
    case sg::Hook::kSessionEnd:
      response.payload = sg::EvaluateSessionEnd(request.payload);
      break;
    case sg::Hook::kPreCompact:
      response.payload = sg::EvaluatePreCompact(request.payload);
      break;
    case sg::Hook::kSubagentStart:
      response.payload = sg::EvaluateSubagentStart(request.payload);
      break;
    case sg::Hook::kSubagentStop:
      response.payload = sg::EvaluateSubagentStop(request.payload);
      break;
    case sg::Hook::kToolError:
      response.payload = sg::EvaluateToolError(request.payload);
      break;
#ifdef SG_HAS_REPOMAP
    case sg::Hook::kRepomapRender:
      response.payload = sg::EvaluateRepomapRender(request.payload);
      break;
#endif
    default:
      response.status = sg::Status::kBadRequest;
      response.payload = "{\"suppressOutput\":true}";
      break;
  }

  return response;
}

}  // namespace

int main(int argc, char** argv) {
  std::string socket_path = DefaultSocketPath();
  bool run_once = false;

  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg == "--socket") {
      if (i + 1 >= argc) {
        PrintUsage(argv[0]);
        return 2;
      }
      socket_path = argv[++i];
      continue;
    }
    if (arg == "--once") {
      run_once = true;
      continue;
    }
    if (arg == "--help" || arg == "-h") {
      PrintUsage(argv[0]);
      return 0;
    }

    std::cerr << "Unknown argument: " << arg << "\n";
    PrintUsage(argv[0]);
    return 2;
  }

  std::signal(SIGINT, SignalHandler);
  std::signal(SIGTERM, SignalHandler);

  sg::ServerOptions options;
  options.socket_path = socket_path;

  sg::ServerHandle server;
  std::string error;
  if (!sg::OpenServer(options, &server, &error)) {
    std::cerr << "sgd: failed to open server socket: " << error << "\n";
    return 1;
  }

  // Compile catalog rules from installed marketplace packages.
  {
    std::string compile_error;
    const auto ext_packages = sg::LoadExternalPackageCatalog();
    if (!sg::CompileCatalogRules(ext_packages, &compile_error)) {
      std::cerr << "sgd: catalog compile error: " << compile_error << "\n";
    }
  }

  // Memory-safety backstop: poll our own RSS in a background thread, abort
  // long-running operations when we exceed the configured cap, and exit so
  // systemd restarts us cleanly. The kernel-level cap (MemoryMax= in
  // sgd.service) is the absolute last line of defense; this watchdog catches
  // the breach earlier and emits a structured event for postmortem.
  // See ~/.mem/asg-repomap-leak-2026-05-01.md for the incident that
  // motivated this.
  (void)sg::StartRssWatchdogFromEnv();

  sg::NotifySystemdReady("sgd online");
  std::cerr << "sgd: listening";
  if (!server.using_systemd_socket) {
    std::cerr << " on " << server.bound_socket_path;
  } else {
    std::cerr << " on systemd-activated fd";
  }
  std::cerr << "\n";

  while (g_running.load()) {
    pollfd pfd{};
    pfd.fd = server.listen_fd;
    pfd.events = POLLIN;
    const int poll_rc = ::poll(&pfd, 1, 500);
    if (poll_rc < 0) {
      if (errno == EINTR) {
        continue;
      }
      std::cerr << "sgd: poll failed: " << std::strerror(errno) << "\n";
      continue;
    }
    if (poll_rc == 0) {
      continue;
    }
    if ((pfd.revents & POLLIN) == 0) {
      continue;
    }

    std::string accept_error;
    const int client_fd = sg::AcceptClient(server.listen_fd, &accept_error);
    if (client_fd < 0) {
      if (!g_running.load()) {
        break;
      }
      std::cerr << "sgd: accept failed: " << accept_error << "\n";
      continue;
    }

    std::vector<std::uint8_t> packet;
    std::string recv_error;
    if (!sg::RecvPacket(client_fd, &packet, &recv_error)) {
      std::cerr << "sgd: recv failed: " << recv_error << "\n";
      sg::CloseFd(client_fd);
      if (run_once) {
        break;
      }
      continue;
    }

    sg::RequestFrame request;
    std::string decode_error;
    sg::ResponseFrame response;
    if (!sg::DecodeRequest(packet, &request, &decode_error)) {
      response.status = sg::Status::kBadRequest;
      response.payload = "{\"suppressOutput\":true}";
    } else {
      response = HandleRequest(request);
      LogIfBlocked(request.hook, request.payload, response.payload);
    }

    const auto encoded = sg::EncodeResponse(response);
    std::string send_error;
    if (!sg::SendPacket(client_fd, encoded, &send_error)) {
      std::cerr << "sgd: send failed: " << send_error << "\n";
    }

    sg::CloseFd(client_fd);
    if (run_once) {
      break;
    }
  }

  sg::NotifySystemdStopping("sgd stopping");
  sg::CleanupServerSocket(server);
  return 0;
}
