#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace sg {

inline constexpr std::size_t kMaxProtocolPayloadBytes = 4 * 1024 * 1024;

enum class Hook : std::uint16_t {
  kUnknown = 0,
  kPreToolUse = 1,
  kPostToolUse = 2,
  kPermissionRequest = 3,
  kReadGuard = 4,
  kReadCompress = 5,
  kStop = 6,
  kSessionStart = 7,
  kSessionEnd = 8,
  kPreCompact = 9,
  kSubagentStart = 10,
  kSubagentStop = 11,
  kToolError = 12,
  // Non-hook RPC ops start at 100 to leave room for future Claude hook phases.
  kRepomapRender = 100,
};

enum class Status : std::uint16_t {
  kOk = 0,
  kBadRequest = 1,
  kInternalError = 2,
};

struct RequestFrame {
  Hook hook = Hook::kUnknown;
  std::string payload;
};

struct ResponseFrame {
  Status status = Status::kOk;
  std::string payload;
};

std::vector<std::uint8_t> EncodeRequest(const RequestFrame& request);
std::vector<std::uint8_t> EncodeResponse(const ResponseFrame& response);

bool DecodeRequest(std::span<const std::uint8_t> packet, RequestFrame* out,
                   std::string* error);
bool DecodeResponse(std::span<const std::uint8_t> packet, ResponseFrame* out,
                    std::string* error);

}  // namespace sg
