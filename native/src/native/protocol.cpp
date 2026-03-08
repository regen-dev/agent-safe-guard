#include "sg/protocol.hpp"

#include <array>

namespace sg {
namespace {

constexpr std::array<std::uint8_t, 4> kMagic = {'S', 'G', 'D', '1'};
constexpr std::uint16_t kVersion = 1;
constexpr std::uint16_t kFrameRequest = 1;
constexpr std::uint16_t kFrameResponse = 2;
constexpr std::size_t kHeaderSize = 16;
void AppendU16(std::vector<std::uint8_t>* out, std::uint16_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
}

void AppendU32(std::vector<std::uint8_t>* out, std::uint32_t value) {
  out->push_back(static_cast<std::uint8_t>(value & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
  out->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
}

std::uint16_t ReadU16(const std::span<const std::uint8_t> bytes,
                      const std::size_t offset) {
  return static_cast<std::uint16_t>(bytes[offset]) |
         (static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
}

std::uint32_t ReadU32(const std::span<const std::uint8_t> bytes,
                      const std::size_t offset) {
  return static_cast<std::uint32_t>(bytes[offset]) |
         (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::vector<std::uint8_t> EncodeCommon(std::uint16_t frame_type, std::uint16_t code,
                                       const std::string& payload) {
  const auto payload_size = static_cast<std::uint32_t>(payload.size());
  std::vector<std::uint8_t> out;
  out.reserve(kHeaderSize + payload_size);

  out.insert(out.end(), kMagic.begin(), kMagic.end());
  AppendU16(&out, kVersion);
  AppendU16(&out, frame_type);
  AppendU16(&out, code);
  AppendU16(&out, 0);
  AppendU32(&out, payload_size);
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

bool DecodeCommon(std::span<const std::uint8_t> packet, std::uint16_t expected_type,
                  std::uint16_t* code, std::string* payload, std::string* error) {
  if (packet.size() < kHeaderSize) {
    if (error != nullptr) {
      *error = "packet too small";
    }
    return false;
  }
  if (packet[0] != kMagic[0] || packet[1] != kMagic[1] || packet[2] != kMagic[2] ||
      packet[3] != kMagic[3]) {
    if (error != nullptr) {
      *error = "invalid magic";
    }
    return false;
  }

  const auto version = ReadU16(packet, 4);
  if (version != kVersion) {
    if (error != nullptr) {
      *error = "unsupported version";
    }
    return false;
  }

  const auto frame_type = ReadU16(packet, 6);
  if (frame_type != expected_type) {
    if (error != nullptr) {
      *error = "unexpected frame type";
    }
    return false;
  }

  const auto payload_size = static_cast<std::size_t>(ReadU32(packet, 12));
  if (payload_size > kMaxProtocolPayloadBytes) {
    if (error != nullptr) {
      *error = "payload exceeds hard limit";
    }
    return false;
  }

  if (kHeaderSize + payload_size != packet.size()) {
    if (error != nullptr) {
      *error = "payload size mismatch";
    }
    return false;
  }

  if (code != nullptr) {
    *code = ReadU16(packet, 8);
  }
  if (payload != nullptr) {
    payload->assign(reinterpret_cast<const char*>(packet.data() + kHeaderSize),
                    payload_size);
  }

  return true;
}

}  // namespace

std::vector<std::uint8_t> EncodeRequest(const RequestFrame& request) {
  return EncodeCommon(kFrameRequest, static_cast<std::uint16_t>(request.hook),
                      request.payload);
}

std::vector<std::uint8_t> EncodeResponse(const ResponseFrame& response) {
  return EncodeCommon(kFrameResponse, static_cast<std::uint16_t>(response.status),
                      response.payload);
}

bool DecodeRequest(std::span<const std::uint8_t> packet, RequestFrame* out,
                   std::string* error) {
  std::uint16_t hook_code = 0;
  std::string payload;
  if (!DecodeCommon(packet, kFrameRequest, &hook_code, &payload, error)) {
    return false;
  }

  if (out != nullptr) {
    out->hook = static_cast<Hook>(hook_code);
    out->payload = std::move(payload);
  }
  return true;
}

bool DecodeResponse(std::span<const std::uint8_t> packet, ResponseFrame* out,
                    std::string* error) {
  std::uint16_t status_code = 0;
  std::string payload;
  if (!DecodeCommon(packet, kFrameResponse, &status_code, &payload, error)) {
    return false;
  }

  if (out != nullptr) {
    out->status = static_cast<Status>(status_code);
    out->payload = std::move(payload);
  }
  return true;
}

}  // namespace sg
