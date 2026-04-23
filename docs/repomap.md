# Repomap Module

`sg_repomap` gives Claude Code a ranked, token-efficient structural map of
the current repository at SessionStart, so it stops re-reading the same
files at the start of every session.

Ported from aider's RepoMap algorithm to native C++20 (no Python). Runs
inside the existing `sgd` daemon via `Hook::kRepomapRender`. See
[../AST.md](../AST.md) for the full design doc that planned the phased
port.

## How it works

1. `asg-repomap` or the daemon walks the repo, collecting `.ts` / `.mts`
   / `.cts` / `.js` / `.mjs` / `.cjs` files. TypeScript declaration files
   (`.d.ts`) are skipped — type-only, enormously noisy. Directory skip
   list: `.git`, `node_modules`, `vendor`, `build`, `dist`, `.next`,
   `coverage`, `__pycache__`, `.venv`, `target`, `release`, `win-unpacked`,
   `mac-unpacked`, `linux-unpacked`, `out`, `.turbo`, `.parcel-cache`,
   `.cache`, `.yarn`, `bower_components`, and `.asg-repomap` itself.

2. Each file is parsed with tree-sitter. A bundled `.scm` query
   (vendored under `native/queries/`) captures `@name.definition.*` and
   `@name.reference.*` nodes. Per-file output is a list of
   `Tag{line, kind, subkind, name}`.

3. A file graph is built: for every identifier that is referenced in
   file A and defined in file B, add an edge `A → B`. Edge weights use
   identifier-shape heuristics:
   - `len ≥ 8` with camelCase / snake_case / kebab-case: ×10
   - starts with `_`: ×0.1
   - defined in more than 5 files: ×0.1 (applied on top)

4. Hand-rolled PageRank (power iteration, damping 0.85, 50 iters max,
   tol 1e-6, dangling-mass redistribution) produces `RankedFile[]`.

5. Top-N files' tags are rendered as `rel_path:line kind subkind name`.
   Binary search on N finds the largest slice that fits under
   `SG_REPOMAP_MAX_TOKENS` (chars/4 approximation). Per-file tag cap
   (default 40) prevents barrel re-export files from starving the rest.

6. Results are cached at `<repo>/.asg-repomap/tags.v1.bin`. Subsequent
   runs mtime-check each file and only reparse what changed. On git
   repos, first build appends `.asg-repomap/` to `.git/info/exclude` so
   the cache never accidentally gets committed.

## CLI

```bash
asg-repomap build  --file <path> [--tags]           # single-file inspection
asg-repomap build  --root <path> [--force]          # full cache build
asg-repomap update --root <path>                    # incremental (mtime-skip)
asg-repomap rank   --root <path>                    # ranked file list only
asg-repomap render --root <path> [--budget N] [--refs] [--max-tags-per-file N]
asg-repomap stats  --root <path>                    # cache stats
asg-repomap clean  --root <path>                    # rm -rf .asg-repomap/
```

## SessionStart integration

`sg-hook-session-start` calls the daemon twice:

1. Normal SessionStart exchange (budget, session tracking — unchanged).
2. If `SG_FEATURE_REPOMAP=1` and session-start didn't already deny,
   send `Hook::kRepomapRender` with `{cwd, budget}`. The daemon runs
   `EnsureFresh + RankFiles + RenderTopN` and returns JSON:
   ```json
   {"ok":true,"files":N,"tags":M,"tokens":T,"budget":B,"text":"..."}
   ```
   The client wraps the text as `additionalContext`:
   ```json
   {"hookSpecificOutput":{"hookEventName":"SessionStart",
     "additionalContext":"<render>"}}
   ```
3. On any error (no source files, bad cwd, corrupt cache) the client
   falls back to the session-start response alone — repomap is never a
   safety gate.

## Configuration

Repomap-specific knobs live in `~/.claude/.safeguard/config.env` and
`features.env`. All respect env-var overrides.

| Variable | Default | Meaning |
|---|---|---|
| `SG_FEATURE_REPOMAP` | `1` | Toggle SessionStart injection (features.env) |
| `SG_REPOMAP_MAX_TOKENS` | `4096` | Render budget (chars/4 approximation) |
| `SG_REPOMAP_MAX_FILE_BYTES` | `524288` | Skip source files > 512 KB |
| `SG_REPOMAP_MAX_TAGS_PER_FILE` | `40` | Per-file tag cap |

`SG_REPOMAP_MAX_TOKENS=1024` was the original plan in AST.md but real
repos have top-1 files bigger than that — we bumped to 4096 (fits 3–4
files on typical TypeScript codebases). See measurements below.

## Measurements

Collected on Ryzen 9 9950X3D + DDR5-3600 on 2026-04-23, single-threaded,
running the native `asg-repomap` CLI against the user's active working
repos. Cold build = empty cache. Warm update = `asg-repomap update`
with nothing changed on disk.

| Repo     | Source files (post-skip) | Cold build | Warm update | Cache size |
|---       |---                       |---         |---          |---         |
| `fab`    | 370                      | 3.3 s      | 10 ms       | 1.0 MB     |
| `ronald` | 1 227                    | 10.0 s     | 40 ms       | 3.1 MB     |
| `sau`    | 3 235                    | 21.6 s     | 100 ms      | 6.8 MB     |

Per-file cold-build throughput: ~115–150 files/s, dominated by
tree-sitter parse time (query compile is one-shot). RSS peaks at 60 MB
on sau (3k files).

### Render at increasing budgets (from the cache)

| Repo     | `--budget 2048`                 | `--budget 4096`                  | `--budget 8192`                   |
|---       |---                              |---                               |---                                |
| `fab`    | 1 file / 40 tags / 971 tokens   | 4 files / 160 tags / 4 020 tokens | 10 files / 323 tags / 8 092 tokens |
| `ronald` | 1 file / 40 tags / 1 379 tokens | 3 files / 120 tags / 3 785 tokens | 6 files / 240 tags / 7 580 tokens  |
| `sau`    | 1 file / 40 tags / 1 270 tokens | 3 files / 120 tags / 3 788 tokens | 6 files / 240 tags / 7 580 tokens  |

Render itself is 10–180 ms on these repos: build (from cache) + PageRank
+ sort + format. No per-call tree-sitter work — the cache is authoritative.

### Success criteria vs AST.md

| Criterion (AST.md §1)                                   | Result             |
|---                                                      |---                 |
| Cold build on ~2k-file TS repo < 30 s                   | **pass** (10 s at 1.2k; 21.6 s at 3.2k) |
| Warm build < 5 s                                        | **pass** (≤ 100 ms with cache) |
| Output fits `SG_REPOMAP_MAX_TOKENS` budget              | **pass** (binary search converges) |
| Incremental update on one file edit < 100 ms            | **pass** (~10–100 ms full `update`, no single-file API needed) |
| Zero extra work for the agent (map arrives on first ctx) | **pass** (SessionStart hook injection) |

## Tuning & known limits

- **Per-file cap matters**. Without `SG_REPOMAP_MAX_TAGS_PER_FILE`, a
  single barrel file (`export * from ...`) can consume the entire
  budget and starve everything else. The default of 40 is empirical —
  enough to cover most classes + top-level functions in one file.

- **Skip list isn't a full .gitignore parser**. We hardcode the common
  output-directory names. Users with exotic layouts can still see
  noise; a future Phase 8 task is to parse `.gitignore` / `git
  ls-files` properly.

- **`.d.ts` is excluded on purpose**. Declaration files add thousands
  of pure-type defs that never refer to each other in a way PageRank
  can use, and bloat the rank pointlessly.

- **TSX not yet supported**. `.tsx` files get skipped (not parsed).
  Phase 8 is the time to add `tree-sitter-typescript/tsx/src/` as a
  separate grammar + a TSX-tags `.scm`.

- **PageRank is file-level**, not symbol-level. This intentionally
  matches aider — symbol-level rank sounds nicer but produces worse
  maps in practice because one popular name can overshadow an
  entire poorly-factored module.

## Troubleshooting

```bash
# What does the map actually look like on my repo?
asg-repomap render --root . --budget 4096 | head -40

# What's ranked first?
asg-repomap rank --root . | head -10

# How big is the cache?
asg-repomap stats --root .

# Nuke and rebuild from scratch.
asg-repomap clean --root .
asg-repomap build --root . --force
```

Daemon-side, the BLOCKED journal log is orthogonal — repomap never
blocks. If additionalContext isn't showing up:

```bash
# Is the feature enabled?
grep SG_FEATURE_REPOMAP ~/.claude/.safeguard/features.env

# Did the session-start exchange get an ok response?
journalctl -b --user-unit=asg.service --since '5 minutes ago' | rg repomap
```
