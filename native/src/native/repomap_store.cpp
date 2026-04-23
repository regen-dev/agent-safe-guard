#include "sg/repomap_store.hpp"

#include "sg/repomap_index.hpp"
#include "sg/repomap_parser.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace sg::repomap {

namespace fs = std::filesystem;

namespace {

constexpr std::array<char, 8> kMagic = {'A', 'S', 'G', 'R', 'M', 'A', 'P', '1'};
constexpr std::uint32_t kCurrentVersion = 1;

void AppendU32LE(std::string* out, std::uint32_t value) {
  out->push_back(static_cast<char>(value & 0xFF));
  out->push_back(static_cast<char>((value >> 8) & 0xFF));
  out->push_back(static_cast<char>((value >> 16) & 0xFF));
  out->push_back(static_cast<char>((value >> 24) & 0xFF));
}

void AppendU64LE(std::string* out, std::uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out->push_back(static_cast<char>((value >> (i * 8)) & 0xFF));
  }
}

void AppendU16LE(std::string* out, std::uint16_t value) {
  out->push_back(static_cast<char>(value & 0xFF));
  out->push_back(static_cast<char>((value >> 8) & 0xFF));
}

bool ReadU32LE(std::string_view buf, std::size_t* off, std::uint32_t* out) {
  if (*off + 4 > buf.size()) return false;
  *out = static_cast<std::uint8_t>(buf[*off]) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(buf[*off + 1])) << 8) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(buf[*off + 2])) << 16) |
         (static_cast<std::uint32_t>(static_cast<std::uint8_t>(buf[*off + 3])) << 24);
  *off += 4;
  return true;
}

bool ReadU64LE(std::string_view buf, std::size_t* off, std::uint64_t* out) {
  if (*off + 8 > buf.size()) return false;
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v |= static_cast<std::uint64_t>(static_cast<std::uint8_t>(buf[*off + i])) << (i * 8);
  }
  *out = v;
  *off += 8;
  return true;
}

bool ReadU16LE(std::string_view buf, std::size_t* off, std::uint16_t* out) {
  if (*off + 2 > buf.size()) return false;
  *out = static_cast<std::uint16_t>(
      static_cast<std::uint8_t>(buf[*off]) |
      (static_cast<std::uint16_t>(static_cast<std::uint8_t>(buf[*off + 1])) << 8));
  *off += 2;
  return true;
}

bool ReadBytes(std::string_view buf, std::size_t* off, std::size_t n,
               std::string* out) {
  if (*off + n > buf.size()) return false;
  out->assign(buf.data() + *off, n);
  *off += n;
  return true;
}

bool ReadFileBinary(const fs::path& path, std::string* out) {
  std::ifstream in(path, std::ios::in | std::ios::binary);
  if (!in.is_open()) return false;
  in.seekg(0, std::ios::end);
  const auto size = in.tellg();
  if (size < 0) return false;
  in.seekg(0, std::ios::beg);
  out->resize(static_cast<std::size_t>(size));
  if (size > 0) in.read(out->data(), size);
  return in.good() || in.eof();
}

bool WriteFileAtomic(const fs::path& path, std::string_view content,
                     std::string* error) {
  const fs::path tmp = path.string() + ".tmp";
  std::error_code ec;
  fs::create_directories(path.parent_path(), ec);
  {
    std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
      *error = "cannot open " + tmp.string() + ": " + std::strerror(errno);
      return false;
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!out.good()) {
      *error = "write failed on " + tmp.string();
      return false;
    }
  }
  fs::rename(tmp, path, ec);
  if (ec) {
    *error = "rename " + tmp.string() + " -> " + path.string() + ": " +
             ec.message();
    return false;
  }
  return true;
}

}  // namespace

fs::path CacheDirForRoot(std::string_view repo_root) {
  return fs::path(repo_root) / kCacheDirName;
}

fs::path CacheFileForRoot(std::string_view repo_root) {
  return CacheDirForRoot(repo_root) / kCacheFileName;
}

bool CacheExists(std::string_view repo_root) {
  std::error_code ec;
  return fs::exists(CacheFileForRoot(repo_root), ec);
}

bool WriteCache(const Index& idx, std::string* error) {
  std::string buf;
  buf.reserve(1024);
  buf.append(kMagic.data(), kMagic.size());
  AppendU32LE(&buf, kCurrentVersion);
  AppendU32LE(&buf, static_cast<std::uint32_t>(idx.files.size()));

  for (const auto& file : idx.files) {
    AppendU32LE(&buf, static_cast<std::uint32_t>(file.rel_path.size()));
    buf.append(file.rel_path);
    AppendU64LE(&buf, file.mtime_ns);
    AppendU64LE(&buf, file.size_bytes);
    AppendU32LE(&buf, static_cast<std::uint32_t>(file.tags.size()));
    for (const auto& tag : file.tags) {
      AppendU32LE(&buf, tag.line);
      buf.push_back(static_cast<char>(tag.kind));
      buf.push_back(static_cast<char>(
          tag.subkind.size() > 255 ? 255 : tag.subkind.size()));
      const auto sub_len =
          static_cast<std::uint8_t>(buf[buf.size() - 1]);
      buf.append(tag.subkind.data(), sub_len);
      const auto name_len = static_cast<std::uint16_t>(
          tag.name.size() > 65535 ? 65535 : tag.name.size());
      AppendU16LE(&buf, name_len);
      buf.append(tag.name.data(), name_len);
    }
  }

  return WriteFileAtomic(CacheFileForRoot(idx.repo_root), buf, error);
}

bool ReadCache(std::string_view repo_root, Index* out, std::string* error) {
  const fs::path path = CacheFileForRoot(repo_root);
  std::string buf;
  if (!ReadFileBinary(path, &buf)) {
    *error = "cannot read " + path.string();
    return false;
  }
  if (buf.size() < kMagic.size() + 4 + 4) {
    *error = "cache too small";
    return false;
  }
  if (std::memcmp(buf.data(), kMagic.data(), kMagic.size()) != 0) {
    *error = "bad magic";
    return false;
  }
  std::size_t off = kMagic.size();
  std::uint32_t version = 0;
  if (!ReadU32LE(buf, &off, &version) || version != kCurrentVersion) {
    *error = "unsupported cache version";
    return false;
  }
  std::uint32_t file_count = 0;
  if (!ReadU32LE(buf, &off, &file_count)) {
    *error = "missing file_count";
    return false;
  }
  out->repo_root = std::string(repo_root);
  out->files.clear();
  out->files.reserve(file_count);
  for (std::uint32_t i = 0; i < file_count; ++i) {
    FileEntry entry;
    std::uint32_t path_len = 0;
    if (!ReadU32LE(buf, &off, &path_len) ||
        !ReadBytes(buf, &off, path_len, &entry.rel_path) ||
        !ReadU64LE(buf, &off, &entry.mtime_ns) ||
        !ReadU64LE(buf, &off, &entry.size_bytes)) {
      *error = "truncated file entry";
      return false;
    }
    std::uint32_t tag_count = 0;
    if (!ReadU32LE(buf, &off, &tag_count)) {
      *error = "missing tag_count";
      return false;
    }
    entry.tags.reserve(tag_count);
    for (std::uint32_t t = 0; t < tag_count; ++t) {
      Tag tag;
      std::uint32_t line = 0;
      if (!ReadU32LE(buf, &off, &line) || off + 2 > buf.size()) {
        *error = "truncated tag";
        return false;
      }
      tag.line = line;
      tag.kind = static_cast<TagKind>(static_cast<std::uint8_t>(buf[off++]));
      const auto sub_len = static_cast<std::uint8_t>(buf[off++]);
      if (!ReadBytes(buf, &off, sub_len, &tag.subkind)) {
        *error = "truncated subkind";
        return false;
      }
      std::uint16_t name_len = 0;
      if (!ReadU16LE(buf, &off, &name_len) ||
          !ReadBytes(buf, &off, name_len, &tag.name)) {
        *error = "truncated name";
        return false;
      }
      entry.tags.push_back(std::move(tag));
    }
    out->files.push_back(std::move(entry));
  }
  // Rebuild derived maps.
  for (std::uint32_t fid = 0; fid < out->files.size(); ++fid) {
    for (const auto& tag : out->files[fid].tags) {
      if (tag.kind == TagKind::kDef) {
        out->defines[tag.name].push_back(fid);
      } else {
        out->references[tag.name].push_back(fid);
      }
    }
  }
  return true;
}

bool RemoveCache(std::string_view repo_root, std::string* error) {
  const fs::path dir = CacheDirForRoot(repo_root);
  std::error_code ec;
  if (!fs::exists(dir, ec)) return true;
  const auto removed = fs::remove_all(dir, ec);
  (void)removed;
  if (ec) {
    *error = "rm -rf " + dir.string() + ": " + ec.message();
    return false;
  }
  return true;
}

bool EnsureGitExclude(std::string_view repo_root, std::string* error) {
  fs::path git_info = fs::path(repo_root) / ".git" / "info";
  std::error_code ec;
  if (!fs::exists(git_info, ec)) return true;  // not a git repo
  fs::path exclude = git_info / "exclude";
  const std::string needle = ".asg-repomap/";

  std::string existing;
  if (fs::exists(exclude, ec)) {
    if (!ReadFileBinary(exclude, &existing)) {
      *error = "cannot read " + exclude.string();
      return false;
    }
    // Look for the needle on its own line (simple substring check is fine;
    // .git/info/exclude is a plain glob file).
    if (existing.find(needle) != std::string::npos) return true;
  }
  if (!existing.empty() && existing.back() != '\n') existing.push_back('\n');
  existing.append(needle);
  existing.push_back('\n');
  return WriteFileAtomic(exclude, existing, error);
}

}  // namespace sg::repomap
