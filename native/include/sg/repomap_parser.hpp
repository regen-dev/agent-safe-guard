#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace sg::repomap {

enum class Language : std::uint8_t {
  kUnknown = 0,
  kTypeScript,
  kJavaScript,
};

enum class TagKind : std::uint8_t {
  kDef = 1,
  kRef = 2,
};

struct Tag {
  std::uint32_t line = 0;   // 1-based source line
  TagKind kind = TagKind::kDef;
  std::string subkind;      // "function", "method", "class", "type", ...
  std::string name;         // identifier text
};

struct ParseStats {
  Language language = Language::kUnknown;
  std::size_t bytes = 0;
  std::size_t node_count = 0;
  std::size_t tag_count = 0;
  bool ok = false;
};

struct ParseResult {
  ParseStats stats;
  std::vector<Tag> tags;
  std::string error;
};

const char* LanguageName(Language lang);
const char* TagKindName(TagKind kind);

Language DetectLanguage(std::string_view path);

// Parse a source file and return node count + extracted tags.
// If only node_count is needed, pass extract_tags=false.
ParseResult ParseFile(std::string_view path, bool extract_tags = true);

}  // namespace sg::repomap
