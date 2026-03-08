#pragma once

#include "sg/rule_types.hpp"

#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace sg {

using RuleMatcher = std::function<std::optional<RuleOutcome>(const Transaction&)>;

struct CompiledRule {
  RuleMetadata meta;
  RuleMatcher match;
};

struct RuleEngineError {
  RuleMetadata meta;
  std::string message;
};

struct EngineResult {
  std::vector<EvaluatedRule> matches;
  std::optional<EvaluatedRule> enforced;
  std::vector<RuleEngineError> errors;
};

PackageMode ResolvePackageMode(std::string_view package_name);
PackageMode ResolveEffectiveRuleMode(const RuleMetadata& meta);
EngineResult EvaluateRules(const Transaction& tx,
                           std::span<const CompiledRule> rules);

}  // namespace sg
