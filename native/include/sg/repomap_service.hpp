#pragma once

#include "sg/repomap_index.hpp"

#include <string>
#include <string_view>

namespace sg::repomap {

struct EnsureOptions {
  BuildOptions build = {};
  bool force_rebuild = false;   // ignore cache if present
  bool persist_cache = true;    // write cache after building/updating
  bool write_git_exclude = true;
};

struct EnsureStats {
  std::size_t files_total = 0;
  std::size_t files_reparsed = 0;
  std::size_t files_added = 0;
  std::size_t files_dropped = 0;
  bool used_cache = false;
  bool wrote_cache = false;
};

// EnsureFresh loads the cache for `repo_root` (if any), walks the filesystem,
// reparses files that changed or were added, drops files that disappeared,
// and writes the cache back out. On first run for a repo, this is equivalent
// to BuildIndex + WriteCache. Returns the up-to-date Index.
Index EnsureFresh(std::string_view repo_root, const EnsureOptions& opts,
                  EnsureStats* stats, std::string* error);

}  // namespace sg::repomap
