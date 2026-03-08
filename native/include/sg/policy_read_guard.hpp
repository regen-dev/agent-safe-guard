#pragma once

#include "sg/rule_types.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace sg {

std::string EvaluateReadGuard(std::string_view request_json);
std::vector<RuleMetadata> ListReadGuardRules();

}  // namespace sg
