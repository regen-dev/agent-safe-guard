#include "sg/client_runtime.hpp"
#include "sg/protocol.hpp"

#include <iostream>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view kClientName = "asg-read-compress";
constexpr std::string_view kFeatureKey = "SG_FEATURE_READ_COMPRESS";

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
  if (!sg::ExchangeRequest(socket_path, sg::Hook::kReadCompress, input,
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
