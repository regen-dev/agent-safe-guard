#pragma once

#include "sg/rule_engine.hpp"

namespace sg {

void AppendRuleMatchEvent(const Transaction& tx, const EvaluatedRule& rule);
void AppendRuleErrorEvent(const Transaction& tx, const RuleEngineError& error);

}  // namespace sg
