#include "sg/policy_repomap.hpp"

#include "sg/json_extract.hpp"
#include "sg/repomap_format.hpp"
#include "sg/repomap_index.hpp"
#include "sg/repomap_service.hpp"

#include <cstdlib>
#include <string>
#include <string_view>

namespace sg {

namespace {

constexpr std::size_t kDefaultBudget = 1024;
constexpr std::size_t kMaxBudget = 65536;

int EnvInt(const char* name, int fallback) {
  const char* raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') return fallback;
  try {
    const int v = std::stoi(raw);
    if (v <= 0) return fallback;
    return v;
  } catch (...) {
    return fallback;
  }
}

std::size_t ExtractBudget(std::string_view json) {
  const auto raw = FindJsonString(json, "budget");
  if (raw.has_value() && !raw->empty()) {
    try {
      const int v = std::stoi(*raw);
      if (v > 0) return static_cast<std::size_t>(v);
    } catch (...) {
    }
  }
  // Numeric-value path: also accept plain integer in JSON.
  // FindJsonString handles quoted values; cheap fallback for unquoted:
  const auto pos = json.find("\"budget\"");
  if (pos != std::string_view::npos) {
    auto colon = json.find(':', pos);
    if (colon != std::string_view::npos) {
      std::size_t i = colon + 1;
      while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
      std::size_t end = i;
      while (end < json.size() &&
             (json[end] >= '0' && json[end] <= '9')) {
        ++end;
      }
      if (end > i) {
        try {
          const int v = std::stoi(std::string(json.substr(i, end - i)));
          if (v > 0) return static_cast<std::size_t>(v);
        } catch (...) {
        }
      }
    }
  }
  return static_cast<std::size_t>(
      EnvInt("SG_REPOMAP_MAX_TOKENS", static_cast<int>(kDefaultBudget)));
}

}  // namespace

std::string EvaluateRepomapRender(std::string_view request_json) {
  const std::string cwd =
      FindJsonString(request_json, "cwd")
          .value_or(FindJsonString(request_json, "sg_pwd")
                        .value_or(std::getenv("PWD") != nullptr
                                      ? std::getenv("PWD")
                                      : ""));
  if (cwd.empty()) {
    return "{\"ok\":false,\"error\":\"missing cwd\"}";
  }

  std::size_t budget = ExtractBudget(request_json);
  if (budget > kMaxBudget) budget = kMaxBudget;

  repomap::EnsureOptions ensure_opts;
  const char* max_bytes = std::getenv("SG_REPOMAP_MAX_FILE_BYTES");
  if (max_bytes != nullptr && *max_bytes != '\0') {
    try {
      ensure_opts.build.max_file_bytes =
          static_cast<std::uint64_t>(std::stoull(max_bytes));
    } catch (...) {
    }
  }
  repomap::EnsureStats stats;
  std::string err;
  auto idx = repomap::EnsureFresh(cwd, ensure_opts, &stats, &err);
  if (idx.files.empty()) {
    return "{\"ok\":false,\"error\":\"no source files\"}";
  }

  const auto ranked = repomap::RankFiles(idx);
  repomap::RenderOptions render_opts;
  render_opts.max_tokens = budget;
  render_opts.include_refs = false;
  const auto rendered = repomap::RenderTopN(idx, ranked, render_opts);

  // Emit the final hook response directly, so the client just writes the
  // daemon's payload to stdout. Claude Code's SessionStart contract accepts
  // `hookSpecificOutput.additionalContext`.
  std::string out;
  out.reserve(rendered.text.size() + 128);
  out.append("{\"ok\":true,\"files\":");
  out.append(std::to_string(rendered.file_count));
  out.append(",\"tags\":");
  out.append(std::to_string(rendered.tag_count));
  out.append(",\"tokens\":");
  out.append(std::to_string(rendered.token_estimate));
  out.append(",\"budget\":");
  out.append(std::to_string(budget));
  out.append(",\"text\":\"");
  out.append(JsonEscape(rendered.text));
  out.append("\"}");
  return out;
}

}  // namespace sg
