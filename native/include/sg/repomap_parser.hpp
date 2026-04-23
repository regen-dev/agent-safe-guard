#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace sg::repomap {

enum class Language {
  kUnknown = 0,
  kTypeScript,
  kJavaScript,
};

const char* LanguageName(Language lang);

// Detect language from a filename extension. Recognises .ts/.mts/.cts as
// TypeScript and .js/.mjs/.cjs as JavaScript. Everything else is kUnknown.
// TSX is intentionally not supported in the MVP (see AST.md phase 8).
Language DetectLanguage(std::string_view path);

struct ParseStats {
  Language language = Language::kUnknown;
  std::size_t bytes = 0;
  std::size_t node_count = 0;
  bool ok = false;
};

struct ParseResult {
  ParseStats stats;
  std::string error;  // populated when stats.ok == false
};

// Phase 0 stub: parse a single source file with the matching grammar and
// return the total tree-sitter node count. No tag extraction yet.
ParseResult ParseFile(std::string_view path);

}  // namespace sg::repomap
