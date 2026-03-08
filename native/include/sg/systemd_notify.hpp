#pragma once

#include <string>

namespace sg {

void NotifySystemdReady(const std::string& status);
void NotifySystemdStopping(const std::string& status);

}  // namespace sg
