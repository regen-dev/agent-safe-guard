#pragma once

#include <optional>
#include <string>
#include <string>
#include <string_view>

namespace sg {

std::optional<std::string> FindJsonRaw(std::string_view json,
                                       std::string_view key);
std::optional<std::string> FindJsonString(std::string_view json,
                                          std::string_view key);
std::optional<std::string> FindJsonObject(std::string_view json,
                                          std::string_view key);
std::string JsonEscape(std::string_view input);

}  // namespace sg
