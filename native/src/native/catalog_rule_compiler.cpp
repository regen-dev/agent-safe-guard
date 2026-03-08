#include "sg/catalog_rule_compiler.hpp"

#include "sg/json_extract.hpp"
#include "sg/rule_types.hpp"

#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <unordered_map>
#include <vector>

namespace sg {
namespace {

// Security: max pattern length to limit ReDoS surface.
constexpr std::size_t kMaxPatternLength = 4096;

// Allowed match_field values — prevent catalog rules from reading internal
// transaction fields (budget state, warnings, etc.).
bool IsAllowedMatchField(std::string_view field) {
  return field == "command" || field == "normalized_command" ||
         field == "lower_command" || field == "glob_pattern" ||
         field == "glob_path" || field == "file_path" ||
         field == "content";
}

// Parse action string from catalog JSON.  Only a safe subset is allowed.
RuleAction ParseCatalogAction(std::string_view raw) {
  if (raw == "deny") return RuleAction::kDeny;
  if (raw == "log_only") return RuleAction::kLogOnly;
  if (raw == "append_context") return RuleAction::kAppendContext;
  if (raw == "modify_output") return RuleAction::kModifyOutput;
  if (raw == "allow") return RuleAction::kAllow;
  return RuleAction::kDeny;  // Default for catalog rules.
}

// Build a deny response payload matching the pre_tool_use protocol.
std::string BuildDenyPayload(std::string_view reason) {
  return std::string("{\"hookSpecificOutput\":{\"hookEventName\":"
                     "\"PreToolUse\",\"permissionDecision\":\"deny\","
                     "\"permissionDecisionReason\":\"") +
         JsonEscape(reason) + "\"}}";
}

struct CompiledCatalogState {
  std::mutex mu;
  bool compiled = false;
  std::unordered_map<int, std::vector<CompiledRule>> by_phase;
};

CompiledCatalogState& GetState() {
  static CompiledCatalogState state;
  return state;
}

}  // namespace

bool CompileCatalogRules(const std::vector<PackageCatalogEntry>& packages,
                         std::string* error) {
  auto& state = GetState();
  std::lock_guard lock(state.mu);
  state.by_phase.clear();
  state.compiled = false;

  for (const auto& pkg : packages) {
    for (const auto& meta : pkg.rules) {
      // Rules without pattern are metadata-only (display in UI but no match).
      if (meta.pattern.empty()) {
        continue;
      }

      // Security: enforce pattern length limit.
      if (meta.pattern.size() > kMaxPatternLength) {
        std::cerr << "sgd: catalog rule " << meta.rule_id
                  << " pattern too long (" << meta.pattern.size()
                  << " > " << kMaxPatternLength << "), skipping\n";
        continue;
      }

      if (meta.phase == RulePhase::kUnknown) {
        continue;
      }

      // Determine match_field: default to lower_command for pre_tool_use.
      std::string match_field = meta.match_field;
      if (match_field.empty()) {
        match_field = "lower_command";
      }

      // Security: restrict to known fields.
      if (!IsAllowedMatchField(match_field)) {
        std::cerr << "sgd: catalog rule " << meta.rule_id
                  << " uses disallowed match_field '" << match_field
                  << "', skipping\n";
        continue;
      }

      // Determine match_tool: default to Bash for pre_tool_use.
      std::string match_tool = meta.match_tool;
      if (match_tool.empty()) {
        match_tool = "Bash";
      }

      // Parse action.
      const RuleAction action = meta.action_str.empty()
                                    ? RuleAction::kDeny
                                    : ParseCatalogAction(meta.action_str);
      // Security: catalog rules cannot use fail_closed.
      if (action == RuleAction::kFailClosed) {
        std::cerr << "sgd: catalog rule " << meta.rule_id
                  << " attempted fail_closed action, denied\n";
        continue;
      }

      const std::string message =
          meta.message.empty()
              ? ("Blocked by catalog rule " + meta.name)
              : meta.message;

      // Compile the regex.
      std::shared_ptr<const std::regex> compiled_re;
      try {
        compiled_re = std::make_shared<const std::regex>(
            meta.pattern, std::regex::ECMAScript | std::regex::optimize);
      } catch (const std::regex_error& ex) {
        std::cerr << "sgd: catalog rule " << meta.rule_id
                  << " has invalid regex: " << ex.what() << "\n";
        if (error != nullptr) {
          *error = "rule " + std::to_string(meta.rule_id) +
                   " invalid regex: " + ex.what();
        }
        continue;  // Skip bad rule, don't fail the whole compilation.
      }

      // Build the CompiledRule.
      CompiledRule compiled;
      compiled.meta = meta;

      // Capture by value for the lambda.
      const std::string cap_match_tool = match_tool;
      const std::string cap_match_field = match_field;
      const std::string cap_message = message;
      const RuleAction cap_action = action;
      const std::string deny_payload = BuildDenyPayload(message);

      compiled.match = [compiled_re, cap_match_tool, cap_match_field,
                        cap_message, cap_action,
                        deny_payload](const Transaction& tx)
          -> std::optional<RuleOutcome> {
        // Tool filter: if match_tool is set, only match that tool.
        if (!cap_match_tool.empty() && tx.tool_name != cap_match_tool) {
          return std::nullopt;
        }

        // Extract the field to match against.
        const auto field_value = GetTransactionField(tx, cap_match_field);
        if (!field_value.has_value() || field_value->empty()) {
          return std::nullopt;
        }

        // Run the regex.
        if (!std::regex_search(field_value->begin(), field_value->end(),
                               *compiled_re)) {
          return std::nullopt;
        }

        RuleOutcome outcome;
        outcome.action = cap_action;
        outcome.terminal = (cap_action == RuleAction::kDeny);
        outcome.message = cap_message;
        outcome.matched_field = cap_match_field;
        // Truncate matched value for audit safety.
        const std::string val(*field_value);
        outcome.matched_value = val.substr(0, 200);
        if (cap_action == RuleAction::kDeny) {
          outcome.response_payload = deny_payload;
        }
        return outcome;
      };

      const int phase_key = static_cast<int>(meta.phase);
      state.by_phase[phase_key].push_back(std::move(compiled));
    }
  }

  state.compiled = true;

  // Log summary.
  std::size_t total = 0;
  for (const auto& [_, rules] : state.by_phase) {
    total += rules.size();
  }
  if (total > 0) {
    std::cerr << "sgd: compiled " << total << " catalog rule(s)\n";
  }

  return true;
}

std::span<const CompiledRule> GetCatalogCompiledRules(RulePhase phase) {
  auto& state = GetState();
  std::lock_guard lock(state.mu);
  if (!state.compiled) {
    return {};
  }
  const int key = static_cast<int>(phase);
  const auto it = state.by_phase.find(key);
  if (it == state.by_phase.end()) {
    return {};
  }
  return it->second;
}

std::vector<RuleMetadata> ListCatalogRulesForPhase(RulePhase phase) {
  auto& state = GetState();
  std::lock_guard lock(state.mu);
  std::vector<RuleMetadata> result;
  if (!state.compiled) {
    return result;
  }
  const int key = static_cast<int>(phase);
  const auto it = state.by_phase.find(key);
  if (it == state.by_phase.end()) {
    return result;
  }
  for (const auto& rule : it->second) {
    result.push_back(rule.meta);
  }
  return result;
}

void ClearCatalogCompiledRules() {
  auto& state = GetState();
  std::lock_guard lock(state.mu);
  state.by_phase.clear();
  state.compiled = false;
}

}  // namespace sg
