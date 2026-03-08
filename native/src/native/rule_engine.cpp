#include "sg/rule_engine.hpp"

#include "sg/client_runtime.hpp"
#include "sg/policy_state.hpp"
#include "sg/rule_audit.hpp"

#include <algorithm>
#include <cctype>
#include <exception>
#include <iostream>
#include <string>

namespace sg {
namespace {

std::string Trim(std::string_view input) {
  std::size_t first = 0;
  while (first < input.size() &&
         std::isspace(static_cast<unsigned char>(input[first])) != 0) {
    ++first;
  }
  std::size_t last = input.size();
  while (last > first &&
         std::isspace(static_cast<unsigned char>(input[last - 1])) != 0) {
    --last;
  }
  return std::string(input.substr(first, last - first));
}

std::string UpperSnake(std::string_view input) {
  std::string out;
  out.reserve(input.size());
  for (const unsigned char ch : input) {
    if (std::isalnum(ch) != 0) {
      out.push_back(static_cast<char>(std::toupper(ch)));
      continue;
    }
    out.push_back('_');
  }
  return out;
}

PackageMode ParsePackageMode(std::string_view raw) {
  std::string lowered = Trim(raw);
  std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                 [](unsigned char ch) {
                   return static_cast<char>(std::tolower(ch));
                 });

  if (lowered == "off" || lowered == "0" || lowered == "false" ||
      lowered == "disable" || lowered == "disabled") {
    return PackageMode::kOff;
  }
  if (lowered == "detection_only" || lowered == "detection-only" ||
      lowered == "detect" || lowered == "2") {
    return PackageMode::kDetectionOnly;
  }
  return PackageMode::kOn;
}

}  // namespace

PackageMode ResolvePackageModeFromState(
    std::string_view package_name,
    const std::vector<PackagePolicyState>& states) {
  if (package_name.empty()) {
    return PackageMode::kOn;
  }

  const std::string env_key = "SG_PACKAGE_" + UpperSnake(package_name);
  if (const char* raw = std::getenv(env_key.c_str());
      raw != nullptr && *raw != '\0') {
    return ParsePackageMode(raw);
  }

  const auto policy_mode = FindPackageModeOverride(states, package_name);
  if (policy_mode.has_value()) {
    return *policy_mode;
  }

  const auto configured = ReadFeatureSetting(env_key);
  if (configured.has_value()) {
    return ParsePackageMode(*configured);
  }

  return PackageMode::kOn;
}

PackageMode ResolveEffectiveRuleModeFromState(
    const RuleMetadata& meta, const std::vector<PackagePolicyState>& states) {
  const PackageMode package_mode = ResolvePackageModeFromState(meta.package, states);
  const auto rule_mode = FindRuleModeOverride(states, meta.package, meta.rule_id);
  if (rule_mode.has_value()) {
    return *rule_mode;
  }
  return package_mode;
}

PackageMode ResolvePackageMode(std::string_view package_name) {
  const auto states = LoadPackagePolicyState();
  return ResolvePackageModeFromState(package_name, states);
}

PackageMode ResolveEffectiveRuleMode(const RuleMetadata& meta) {
  const auto states = LoadPackagePolicyState();
  return ResolveEffectiveRuleModeFromState(meta, states);
}

EngineResult EvaluateRules(const Transaction& tx,
                           std::span<const CompiledRule> rules) {
  EngineResult result;
  const auto states = LoadPackagePolicyState();
  for (const auto& rule : rules) {
    const PackageMode mode = ResolveEffectiveRuleModeFromState(rule.meta, states);

    std::optional<RuleOutcome> outcome;
    try {
      outcome = rule.match(tx);
    } catch (const std::exception& ex) {
      if (mode != PackageMode::kOff) {
        result.errors.push_back({rule.meta, ex.what()});
      }
      continue;
    } catch (...) {
      if (mode != PackageMode::kOff) {
        result.errors.push_back({rule.meta, "unknown rule matcher failure"});
      }
      continue;
    }

    if (!outcome.has_value()) {
      continue;
    }

    if (mode == PackageMode::kOff) {
      // Rule matched but was bypassed — audit-only, no enforcement.
      EvaluatedRule bypassed;
      bypassed.meta = rule.meta;
      bypassed.mode = PackageMode::kOff;
      bypassed.action = outcome->action;
      bypassed.terminal = false;
      bypassed.enforced = false;
      bypassed.message = outcome->message;
      bypassed.matched_field = outcome->matched_field;
      bypassed.matched_value = outcome->matched_value;
      AppendRuleMatchEvent(tx, bypassed);
      std::cerr << "sgd: BYPASSED [" << ToString(rule.meta.phase)
                << "] rule=" << rule.meta.rule_id << " ("
                << rule.meta.name << ") tool=" << tx.tool_name
                << " | " << outcome->message << "\n";
      continue;
    }

    EvaluatedRule evaluated;
    evaluated.meta = rule.meta;
    evaluated.mode = mode;
    evaluated.action = outcome->action;
    evaluated.terminal = outcome->terminal;
    evaluated.message = outcome->message;
    evaluated.matched_field = outcome->matched_field;
    evaluated.matched_value = outcome->matched_value;
    evaluated.response_payload = outcome->response_payload;
    result.matches.push_back(evaluated);

    if (mode != PackageMode::kOn || !evaluated.terminal) {
      continue;
    }

    evaluated.enforced = true;
    result.matches.back().enforced = true;
    result.enforced = evaluated;
    break;
  }
  return result;
}

}  // namespace sg
