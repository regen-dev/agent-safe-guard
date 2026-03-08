#pragma once

#include "sg/protocol.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace sg {

inline constexpr std::string_view kClientFailClosedResponse =
    "{\"continue\":false,\"stopReason\":\"agent-safe-guard native runtime unavailable\"}";
inline constexpr std::string_view kClientPassthroughResponse =
    "{\"suppressOutput\":true}";

std::string DefaultSocketPath();
bool DebugEnabled();
void DebugLog(std::string_view client_name, std::string_view message);
int FailClosed(std::string_view client_name, const std::string& reason);
std::optional<std::string> ReadFeatureSetting(std::string_view feature_key);
bool IsFeatureEnabled(std::string_view feature_key);
void EmitPassthrough();
std::string ReadAllStdin();
bool ExchangeRequest(std::string_view socket_path, Hook hook, std::string payload,
                     ResponseFrame* response, std::string* error);
void AppendEnvJsonField(std::string* json, const char* env_name,
                        const char* field_name);
std::filesystem::path DefaultEventsFilePath();
void AppendEventLine(const std::filesystem::path& path,
                     std::string_view json_line);
long UnixNow();

}  // namespace sg
