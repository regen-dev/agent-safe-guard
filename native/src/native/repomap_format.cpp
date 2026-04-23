#include "sg/repomap_format.hpp"

#include "sg/repomap_index.hpp"
#include "sg/repomap_parser.hpp"

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

namespace sg::repomap {

namespace {

struct RenderTag {
  std::string rel_path;
  std::uint32_t line;
  TagKind kind;
  std::string subkind;
  std::string name;
};

bool CompareTags(const RenderTag& a, const RenderTag& b) {
  if (a.rel_path != b.rel_path) return a.rel_path < b.rel_path;
  if (a.line != b.line) return a.line < b.line;
  if (a.kind != b.kind) {
    return static_cast<int>(a.kind) < static_cast<int>(b.kind);
  }
  return a.name < b.name;
}

std::string FormatLines(const std::vector<RenderTag>& tags) {
  std::string out;
  out.reserve(tags.size() * 48);
  for (const auto& t : tags) {
    out.append(t.rel_path);
    out.push_back(':');
    out.append(std::to_string(t.line));
    out.push_back(' ');
    out.append(TagKindName(t.kind));
    out.push_back(' ');
    out.append(t.subkind);
    out.push_back(' ');
    out.append(t.name);
    out.push_back('\n');
  }
  return out;
}

// Rank subkinds so the per-file cap keeps the structurally most useful tags:
// classes/interfaces first, then top-level functions/types/enums, then
// methods, refs last. Deterministic so render output is stable.
int SubkindPriority(TagKind kind, std::string_view subkind) {
  if (kind == TagKind::kDef) {
    if (subkind == "class" || subkind == "interface") return 0;
    if (subkind == "function" || subkind == "type" ||
        subkind == "enum" || subkind == "module") return 1;
    if (subkind == "method") return 2;
    return 3;
  }
  return 10;  // refs always last
}

RenderResult RenderForN(const Index& idx,
                        const std::vector<RankedFile>& ranked,
                        std::size_t n, bool include_refs,
                        std::size_t max_tags_per_file) {
  RenderResult r;
  n = std::min(n, ranked.size());
  std::vector<RenderTag> rtags;
  for (std::size_t i = 0; i < n; ++i) {
    const auto& file = idx.files[ranked[i].file_id];
    std::vector<RenderTag> file_tags;
    for (const auto& tag : file.tags) {
      if (!include_refs && tag.kind != TagKind::kDef) continue;
      file_tags.push_back({file.rel_path, tag.line, tag.kind, tag.subkind,
                           tag.name});
    }
    if (max_tags_per_file > 0 && file_tags.size() > max_tags_per_file) {
      // Keep the structurally most useful tags first, then order the slice
      // by file/line for the final output.
      std::stable_sort(file_tags.begin(), file_tags.end(),
                       [](const RenderTag& a, const RenderTag& b) {
                         const int pa = SubkindPriority(a.kind, a.subkind);
                         const int pb = SubkindPriority(b.kind, b.subkind);
                         if (pa != pb) return pa < pb;
                         return a.line < b.line;
                       });
      file_tags.resize(max_tags_per_file);
    }
    rtags.insert(rtags.end(), file_tags.begin(), file_tags.end());
  }
  std::sort(rtags.begin(), rtags.end(), CompareTags);
  r.text = FormatLines(rtags);
  r.file_count = n;
  r.tag_count = rtags.size();
  r.token_estimate = ApproximateTokens(r.text);
  return r;
}

}  // namespace

std::size_t ApproximateTokens(std::string_view text) {
  return (text.size() + 3) / 4;
}

RenderResult RenderTopN(const Index& idx,
                        const std::vector<RankedFile>& ranked,
                        const RenderOptions& opts) {
  const std::size_t total = ranked.size();
  if (total == 0) return {};

  // First check whether *all* files fit. If yes, just return that.
  RenderResult full =
      RenderForN(idx, ranked, total, opts.include_refs, opts.max_tags_per_file);
  if (full.token_estimate <= opts.max_tokens) {
    return full;
  }

  // Binary search on top_n. lo is known to fit (at least the guaranteed
  // minimum), hi is known to overflow.
  std::size_t lo = std::min(opts.min_files_guaranteed, total);
  std::size_t hi = total;
  RenderResult best;
  best =
      RenderForN(idx, ranked, lo, opts.include_refs, opts.max_tags_per_file);
  while (lo < hi) {
    const std::size_t mid = lo + (hi - lo + 1) / 2;
    RenderResult cand = RenderForN(idx, ranked, mid, opts.include_refs,
                                   opts.max_tags_per_file);
    if (cand.token_estimate <= opts.max_tokens) {
      best = std::move(cand);
      lo = mid;
    } else {
      hi = mid - 1;
    }
  }
  best.truncated = (best.file_count < total);
  return best;
}

}  // namespace sg::repomap
