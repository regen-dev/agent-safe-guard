#pragma once

#include <optional>
#include <string>
#include <vector>

namespace sg {

struct ProcessResult {
  int exit_code = -1;
  std::string stdout_text;
  std::string stderr_text;
};

ProcessResult RunProcess(const std::vector<std::string>& argv,
                         const std::optional<std::string>& stdin_text = std::nullopt);
int ExecProcess(const std::vector<std::string>& argv);
int SpawnAndWait(const std::vector<std::string>& argv);

}  // namespace sg
