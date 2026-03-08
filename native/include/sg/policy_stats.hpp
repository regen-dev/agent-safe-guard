#pragma once

#include "sg/rule_engine.hpp"

namespace sg {

struct RuleStatsSnapshot {
  int rule_id = 0;
  std::string package;
  std::string rule_name;
  std::string phase;
  std::string severity;
  long matched_total = 0;
  long blocked_total = 0;
  long allowed_total = 0;
  long suppressed_total = 0;
  long modified_total = 0;
  long detect_only_total = 0;
  long error_total = 0;
  long last_matched_at = 0;
  long last_blocked_at = 0;
  long last_error_at = 0;
  std::string last_disposition;
  std::string last_project;
  std::string last_session_id;
};

struct PackageStatsSnapshot {
  std::string package;
  long matched_total = 0;
  long blocked_total = 0;
  long allowed_total = 0;
  long suppressed_total = 0;
  long modified_total = 0;
  long detect_only_total = 0;
  long error_total = 0;
  long last_matched_at = 0;
  long last_blocked_at = 0;
  long last_error_at = 0;
  std::string last_disposition;
  std::string last_project;
  std::string last_session_id;
};

void UpdateRuleMatchStats(const Transaction& tx, const EvaluatedRule& rule);
void UpdateRuleErrorStats(const Transaction& tx, const RuleEngineError& error);
std::vector<RuleStatsSnapshot> LoadRuleStatsSnapshot();
std::vector<PackageStatsSnapshot> LoadPackageStatsSnapshot();

}  // namespace sg
