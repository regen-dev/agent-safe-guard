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

constexpr std::size_t kDefaultBudget = 4096;
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

bool EnvBool(const char* name, bool fallback) {
  const char* raw = std::getenv(name);
  if (raw == nullptr || *raw == '\0') return fallback;
  const std::string_view s(raw);
  if (s == "1" || s == "true" || s == "TRUE" || s == "yes") return true;
  if (s == "0" || s == "false" || s == "FALSE" || s == "no") return false;
  return fallback;
}

const char* SkipReasonString(repomap::EnsureSkipReason r) {
  switch (r) {
    case repomap::EnsureSkipReason::kNone:        return "none";
    case repomap::EnsureSkipReason::kRootMissing: return "root_missing";
    case repomap::EnsureSkipReason::kUnsafeRoot:  return "unsafe_root";
    case repomap::EnsureSkipReason::kNotGitRepo:  return "not_git_repo";
    case repomap::EnsureSkipReason::kFileCapHit:  return "too_many_files";
  }
  return "unknown";
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
  // Hard cap on the source-file count. Default 5000 is plenty for any real
  // project; the cap exists to refuse $HOME-scale walks. See
  // ~/.mem/asg-repomap-leak-2026-05-01.md.
  ensure_opts.build.max_files = static_cast<std::size_t>(
      EnvInt("SG_REPOMAP_MAX_FILES", 5000));
  ensure_opts.allow_unsafe_root = EnvBool("SG_REPOMAP_ALLOW_UNSAFE_ROOT", false);
  ensure_opts.require_git_root = EnvBool("SG_REPOMAP_REQUIRE_GIT_ROOT", true);

  repomap::EnsureStats stats;
  std::string err;
  auto idx = repomap::EnsureFresh(cwd, ensure_opts, &stats, &err);
  if (stats.skip_reason != repomap::EnsureSkipReason::kNone &&
      stats.skip_reason != repomap::EnsureSkipReason::kFileCapHit) {
    // Hard refusal — surface the reason so the daemon's audit log records
    // *why* the repomap was empty (not just that it failed).
    std::string out;
    out.reserve(128 + err.size());
    out.append("{\"ok\":false,\"error\":\"");
    out.append(JsonEscape(err));
    out.append("\",\"skip_reason\":\"");
    out.append(SkipReasonString(stats.skip_reason));
    out.append("\"}");
    return out;
  }
  if (idx.files.empty()) {
    return "{\"ok\":false,\"error\":\"no source files\"}";
  }

  const auto ranked = repomap::RankFiles(idx);
  repomap::RenderOptions render_opts;
  render_opts.max_tokens = budget;
  render_opts.include_refs = false;
  // Per-file cap prevents barrel re-export files from dominating the budget.
  if (const char* cap = std::getenv("SG_REPOMAP_MAX_TAGS_PER_FILE");
      cap != nullptr && *cap != '\0') {
    try {
      render_opts.max_tags_per_file =
          static_cast<std::size_t>(std::stoul(cap));
    } catch (...) {
    }
  }
  const auto rendered = repomap::RenderTopN(idx, ranked, render_opts);

  // Emit the final hook response directly, so the client just writes the
  // daemon's payload to stdout. Claude Code's SessionStart contract accepts
  // `hookSpecificOutput.additionalContext`.
  std::string out;
  out.reserve(rendered.text.size() + 256);
  out.append("{\"ok\":true,\"files\":");
  out.append(std::to_string(rendered.file_count));
  out.append(",\"tags\":");
  out.append(std::to_string(rendered.tag_count));
  out.append(",\"tokens\":");
  out.append(std::to_string(rendered.token_estimate));
  out.append(",\"budget\":");
  out.append(std::to_string(budget));
  if (stats.skip_reason == repomap::EnsureSkipReason::kFileCapHit) {
    out.append(",\"file_cap_hit\":true");
  }
  out.append(",\"text\":\"");
  out.append(JsonEscape(rendered.text));
  out.append("\"}");
  return out;
}

}  // namespace sg
