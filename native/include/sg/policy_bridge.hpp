#pragma once

#include "sg/rule_types.hpp"

#include <string>
#include <string_view>

namespace sg {

Transaction BuildBridgeTransaction(RulePhase phase, std::string_view request_json,
                                   std::string_view fallback_tool_name = {});
RuleAction InferBridgeAction(std::string_view response,
                             RuleAction default_action = RuleAction::kAllow);
void AppendBridgeRuleMatch(const Transaction& tx, const RuleMetadata& meta,
                           PackageMode mode, RuleAction action, bool enforced,
                           std::string_view message = {},
                           std::string_view matched_field = {},
                           std::string_view matched_value = {});
std::string PassthroughResponse();

}  // namespace sg
