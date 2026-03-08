#pragma once

#include "sg/rule_types.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace sg {

std::string EvaluateSessionEnd(std::string_view request_json);
std::vector<RuleMetadata> ListSessionEndRules();

}  // namespace sg
