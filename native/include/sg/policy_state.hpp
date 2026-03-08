#pragma once

#include "sg/rule_types.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace sg {

struct RuleModeOverride {
  int rule_id = 0;
  PackageMode mode = PackageMode::kOn;
};

struct PackagePolicyState {
  std::string package;
  PackageMode mode = PackageMode::kOn;
  std::vector<RuleModeOverride> rules;
};

std::filesystem::path DefaultPolicyDir();
std::filesystem::path DefaultPackagesStatePath();

std::vector<PackagePolicyState> LoadPackagePolicyState();
bool SavePackagePolicyState(const std::vector<PackagePolicyState>& states,
                           std::string* error = nullptr);
void EnsurePolicyStateScaffold();

std::optional<PackageMode> FindPackageModeOverride(
    const std::vector<PackagePolicyState>& states, std::string_view package_name);
std::optional<PackageMode> FindRuleModeOverride(
    const std::vector<PackagePolicyState>& states, std::string_view package_name,
    int rule_id);

}  // namespace sg
