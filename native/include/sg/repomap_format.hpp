#pragma once

#include "sg/repomap_index.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sg::repomap {

struct RenderOptions {
  std::size_t max_tokens = 1024;       // chars/4 approximation
  bool include_refs = false;            // MVP: defs only — more signal per token
  std::size_t min_files_guaranteed = 0; // always include at least this many files
};

struct RenderResult {
  std::string text;
  std::size_t file_count = 0;
  std::size_t tag_count = 0;
  std::size_t token_estimate = 0;
  bool truncated = false;               // true if we could have shown more
};

// Render the top-N ranked files' tags as `rel_path:line kind name`. Select
// the largest N whose output fits under max_tokens (binary search). Output
// lines are sorted by rel_path ASC, then line ASC, then kind (def before
// ref), then name.
RenderResult RenderTopN(const Index& idx,
                        const std::vector<RankedFile>& ranked,
                        const RenderOptions& opts = {});

// Token estimate used internally — exposed for tests. Currently `chars/4`.
std::size_t ApproximateTokens(std::string_view text);

}  // namespace sg::repomap
