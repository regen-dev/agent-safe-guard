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
  // When true (default), refuse to repomap a directory that is not a git
  // working tree. Prevents accidentally walking $HOME / / / tmp etc. when
  // `claude` is started outside any project.
  bool require_git_root = true;
  // Escape hatch for tests and one-off CLI use. When true, skip both the
  // require_git_root check and the unsafe-root refusal list.
  bool allow_unsafe_root = false;
};

// Why EnsureFresh produced an empty (or partial) index, when applicable.
enum class EnsureSkipReason : std::uint8_t {
  kNone = 0,
  kRootMissing,     // path does not exist or isn't a directory
  kUnsafeRoot,      // path matched the hardcoded refusal list ($HOME, /, ...)
  kNotGitRepo,      // require_git_root && no .git/ marker
  kFileCapHit,      // BuildOptions::max_files exceeded; partial index returned
};

struct EnsureStats {
  std::size_t files_total = 0;
  std::size_t files_reparsed = 0;
  std::size_t files_added = 0;
  std::size_t files_dropped = 0;
  bool used_cache = false;
  bool wrote_cache = false;
  EnsureSkipReason skip_reason = EnsureSkipReason::kNone;
};

// EnsureFresh loads the cache for `repo_root` (if any), walks the filesystem,
// reparses files that changed or were added, drops files that disappeared,
// and writes the cache back out. On first run for a repo, this is equivalent
// to BuildIndex + WriteCache. Returns the up-to-date Index.
//
// Refuses unsafe roots ($HOME, /, /tmp, /var, /etc, /usr, /opt, /mnt, /media)
// and (by default) directories that are not git working trees. See
// `~/.mem/asg-repomap-leak-2026-05-01.md` for the incident that motivated this.
Index EnsureFresh(std::string_view repo_root, const EnsureOptions& opts,
                  EnsureStats* stats, std::string* error);

// True if `path` is one of the hardcoded unsafe roots that EnsureFresh
// refuses by default. Exposed for testing and for callers that want to
// validate before invoking EnsureFresh.
bool IsUnsafeRoot(std::string_view path);

}  // namespace sg::repomap
