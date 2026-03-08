#pragma once

#include "sg/policy_catalog.hpp"
#include "sg/rule_engine.hpp"

#include <span>
#include <string>
#include <vector>

namespace sg {

// Compile catalog rules from installed packages into CompiledRule instances.
// Rules with a non-empty "pattern" field become regex-based matchers.
// Rules without patterns remain metadata-only (UI display, no matching).
// Call once at daemon startup; results are cached internally.
bool CompileCatalogRules(const std::vector<PackageCatalogEntry>& packages,
                         std::string* error = nullptr);

// Get pre-compiled rules for a specific phase.
std::span<const CompiledRule> GetCatalogCompiledRules(RulePhase phase);

// Get metadata for all compiled catalog rules (for ListRules display).
std::vector<RuleMetadata> ListCatalogRulesForPhase(RulePhase phase);

// Discard all compiled rules (test cleanup).
void ClearCatalogCompiledRules();

}  // namespace sg
