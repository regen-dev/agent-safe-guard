#pragma once

#include "sg/repomap_index.hpp"

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

namespace sg::repomap {

// On-disk cache format for the parsed Index.
//
//   [8 bytes]  magic  = "ASGRMAP1"
//   [4 bytes]  version = 1 (little-endian u32)
//   [4 bytes]  file_count (little-endian u32)
//   per file:
//     [4 bytes]  rel_path length (u32)
//     [N bytes]  rel_path utf-8 (no NUL)
//     [8 bytes]  mtime_ns (u64)
//     [8 bytes]  size_bytes (u64)
//     [4 bytes]  tag_count (u32)
//     per tag:
//       [4 bytes]  line (u32)
//       [1 byte]   kind (u8: 1=def, 2=ref)
//       [1 byte]   subkind length (u8)
//       [N bytes]  subkind utf-8
//       [2 bytes]  name length (u16)
//       [N bytes]  name utf-8
//
// Writes go via <path>.tmp + rename for atomicity. Version bumps require
// a new file name (tags.v2.bin) — do not overload v1.
inline constexpr const char* kCacheFileName = "tags.v1.bin";
inline constexpr const char* kCacheDirName  = ".asg-repomap";

std::filesystem::path CacheDirForRoot(std::string_view repo_root);
std::filesystem::path CacheFileForRoot(std::string_view repo_root);

bool WriteCache(const Index& idx, std::string* error);
bool ReadCache(std::string_view repo_root, Index* out, std::string* error);
bool CacheExists(std::string_view repo_root);
bool RemoveCache(std::string_view repo_root, std::string* error);

// Append `.asg-repomap/` to <root>/.git/info/exclude if not already there.
// Silently no-ops for non-git roots. Returns true on success (including
// no-op), false on I/O error.
bool EnsureGitExclude(std::string_view repo_root, std::string* error);

}  // namespace sg::repomap
