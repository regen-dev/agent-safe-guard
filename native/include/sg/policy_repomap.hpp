#pragma once

#include <string>
#include <string_view>

namespace sg {

// Handle a `kRepomapRender` request. Input JSON:
//   {"cwd":"/abs/path","budget":<int>}
// Response JSON (success):
//   {"ok":true,"text":"...","files":N,"tags":M,"tokens":T,"budget":B}
// Response JSON (failure — never fatal, but client should fall back):
//   {"ok":false,"error":"..."}
//
// The daemon uses this for the `sg-hook-session-start` client's second
// exchange. It is deliberately independent from the SessionStart policy
// so it can be used from other clients and from the `asg-repomap` CLI.
std::string EvaluateRepomapRender(std::string_view request_json);

}  // namespace sg
