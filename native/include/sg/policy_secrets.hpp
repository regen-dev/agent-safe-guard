#pragma once

#include "sg/rule_types.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace sg {

std::string EvaluateSecretsReadGuard(std::string_view request_json);
std::string EvaluateSecretsReadCompress(std::string_view request_json);
std::vector<RuleMetadata> ListSecretsRules();

}  // namespace sg
