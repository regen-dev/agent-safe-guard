# AST.md — Repo-Map Module for agent-safe-guard

Port of aider's RepoMap algorithm to native C++20, integrated into asg as a
new module. Goal: give Claude Code a persistent, ranked, token-efficient
structural view of a repository so it stops re-reading files on every
session.

Status: design/plan. No code yet. Execute in a fresh session that starts
from this file.

---

## 1. Goal

Given a repo, produce a compact text "map" like:

```
src/auth.ts:12 class AuthService
src/auth.ts:34 method AuthService.login
src/routes/api.ts:8 function handleLogin
tests/auth.test.ts:5 test "login rejects bad password"
```

Delivered to Claude Code at `SessionStart` as `additionalContext`, fitting
within a configurable token budget, ranked so the most-referenced files
appear first.

### Success criteria

- Build time on `~/src/ronald` (~2k TS/JS files, excluding node_modules):
  < 5 s warm, < 30 s cold
- Output fits `SG_REPOMAP_MAX_TOKENS` (default 1024)
- Incremental update on one file edit: < 100 ms
- Zero extra work for the agent — map arrives in its first context

### Non-goals

- Not an MCP server (no new surface; lives inside existing sgd socket)
- No D3 visualization, no wiki generation, no PageRank/Leiden communities
- No embeddings, no vector search, no HTTP endpoints
- No language support beyond TS + JS in the MVP (TSX in Phase 8)
- Not a replacement for Read/Grep — a *priming* layer so Claude needs fewer
  of them

---

## 2. Why in agent-safe-guard

- Daemon already exists (`sgd`) with Unix socket protocol and systemd wiring
- `session-start` hook client already exists and can emit `additionalContext`
- TDD + fail-closed discipline match what we want for this feature
- Existing `read-compress` hook already does structural summaries in a crude
  way — repo-map is the principled version of the same idea at session scope
- One source tree to maintain; one installer; one uninstaller

No new daemon, no new service, no new user-facing binary beyond a thin
`asg-repomap` CLI for debugging.

---

## 3. Algorithm (aider port)

Aider's RepoMap (~800 LOC Python, verified against
`aider/repomap.py@main`):

1. **Parse** each file with tree-sitter using language-specific `.scm` tag
   queries that capture:
   - `@name.definition.*` → symbol defined here
   - `@name.reference.*` → symbol used here
2. **Extract tags**: `Tag{fname, line, name, kind}` (`kind` ∈ {def, ref})
3. **Build graph**:
   - `defines[ident] = set<file>`
   - `references[ident] = multiset<file>`
   - Edge `(src_file → dst_file)` with weight multiplier based on
     identifier shape:
     - mentioned in chat: ×50 (**skip for MVP** — we don't know "chat" at
       session-start time)
     - long camelCase/snake_case/kebab-case: ×10
     - underscore-prefixed: ×0.1
     - identifier defined in > 5 files: ×0.1
4. **PageRank** over the file-graph (power iteration, 50 iterations, damping
   0.85). Optional personalization vector (skip for MVP)
5. **Select tags** to fit token budget via binary search on `top_n`
6. **Render** as `path:line kind name` lines, sorted by file then line

### What we simplify vs aider

| Feature | Aider | Ours (MVP) |
|--|--|--|
| Pygments fallback for ref extraction | yes | no — rely on tree-sitter queries only |
| TreeContext code-snippet rendering | yes (grep-ast) | no — just `path:line kind name` |
| Chat/mention personalization | yes | no — session-start has no chat yet |
| Cache | SQLite keyed `{path, mtime}` | flat file `<repo>/.asg-repomap/tags.v1.bin` (git-local ignore) |
| Token counting | tiktoken | `len(str) / 4` approximation |
| Language coverage | 20+ via language-pack | TS + JS only (Phase 1); TSX, Pascal, PHP, Python later |
| Graph library | NetworkX | hand-rolled sparse matrix |

---

## 4. Architecture within asg

### New components

```
native/
  include/sg/
    repomap_parser.hpp      # tree-sitter wrapper: file -> vector<Tag>
    repomap_index.hpp       # graph + PageRank + selection
    repomap_store.hpp       # cache I/O (flat file, mtime-keyed)
    repomap_format.hpp      # render vector<Tag> -> string
    repomap_service.hpp     # orchestration: build | update | render
    policy_repomap.hpp      # daemon-side: serves "render" queries
  src/native/
    repomap_parser.cpp
    repomap_index.cpp
    repomap_store.cpp
    repomap_format.cpp
    repomap_service.cpp
    policy_repomap.cpp
  src/tools/
    asg_repomap_main.cpp    # asg-repomap CLI (build | update | render | query)
  queries/                  # tree-sitter .scm tag queries
    typescript-tags.scm
    javascript-tags.scm
```

### New submodules (under `third_party/`)

```
third_party/doctest/                    # github.com/doctest/doctest (header-only)
third_party/tree-sitter/                # github.com/tree-sitter/tree-sitter
third_party/tree-sitter-typescript/     # github.com/tree-sitter/tree-sitter-typescript (MVP uses only the typescript/ subdir, not tsx/)
third_party/tree-sitter-javascript/     # github.com/tree-sitter/tree-sitter-javascript
```

Pin to specific tags. Build grammar libs as C static libs via CMake.
Link into a new `sg_repomap` static lib (not `sg_common`).

### Data flow

```
                      ┌──────────── repomap build ─────────────┐
                      │                                         │
  file(s) ──► parser ─┤      ┌── cache read ──┐                 │
                      │      ▼                │                 │
                      └► Tag[] ──► index ──► PageRank ──► selection
                             │                                  │
                             ▼                                  ▼
                        cache write                           format
                                                                │
                                                                ▼
                                                         additionalContext
```

### Hook integration

- `sg-hook-session-start` calls daemon with `{op:"repomap_render", cwd, budget}`
- Daemon calls `policy_repomap::Render(cwd, budget)`:
  1. `repomap_service::EnsureFresh(cwd)` — cheap mtime scan, reparse changed files
  2. `repomap_service::Render(budget)` — return string
- Hook client merges the string into its SessionStart JSON output under
  `hookSpecificOutput.additionalContext`
- Fail-closed path: any error in `policy_repomap` is **non-fatal** for
  session-start (we log and emit passthrough). Session-start must never
  fail because of repo-map — it's an optimization, not a safety gate

This is the one deviation from asg's strict fail-closed rule, justified by:
repo-map is *not* a safety check, and blocking session-start on index
errors would be worse than just not having the map.

---

## 5. Data structures

```cpp
struct Tag {
  uint32_t file_id;   // index into file table
  uint32_t line;      // 1-based
  uint16_t kind;      // enum: Def=1, Ref=2
  uint16_t name_len;
  char name[];        // flexible array, packed in cache
};

struct FileEntry {
  std::string rel_path;    // relative to repo root
  uint64_t mtime_ns;
  uint64_t size_bytes;
  uint64_t sha256_hi;      // optional; skip recompute if mtime matches
  uint64_t sha256_lo;
  std::vector<Tag> tags;
};

struct RepoIndex {
  std::string repo_root;          // abs path
  std::vector<FileEntry> files;
  // derived (rebuilt on load, not serialized):
  std::unordered_map<std::string, std::vector<uint32_t>> defines;    // ident -> file_ids
  std::unordered_map<std::string, std::vector<uint32_t>> references; // ident -> file_ids
};

struct RankedFile {
  uint32_t file_id;
  double score;
};
```

### Cache format (v1)

`<repo_root>/.asg-repomap/tags.v1.bin`

On first build, `asg-repomap build` appends `.asg-repomap/` to
`<repo_root>/.git/info/exclude` (git-local, never modifies `.gitignore`).
Non-git repos just create the dir with no ignore handling.

Flat binary, little-endian:

```
[8 bytes] magic "ASGRMAP1"
[4 bytes] version = 1
[4 bytes] file_count
for each file:
  [4 bytes] path_len
  [N bytes] rel_path (utf-8, no NUL)
  [8 bytes] mtime_ns
  [8 bytes] size_bytes
  [4 bytes] tag_count
  for each tag:
    [4 bytes] line
    [2 bytes] kind
    [2 bytes] name_len
    [N bytes] name
```

No compression — these files stay small (a 2k-file TS repo gives ~200 KB).

---

## 6. Tree-sitter tag queries (.scm)

Copy and trim aider's queries (they're MIT) and commit under
`native/queries/`. MVP: TS + JS. Each query captures only what we
actually use: defs (function, class, method) and refs (call expressions,
identifier references).

### Minimal TS query (sketch — real one bigger)

```scheme
; definitions
(function_declaration name: (identifier) @name.definition.function)
(method_definition name: (property_identifier) @name.definition.method)
(class_declaration name: (type_identifier) @name.definition.class)

; references
(call_expression function: (identifier) @name.reference.call)
(call_expression function: (member_expression property: (property_identifier) @name.reference.call))
(new_expression constructor: (identifier) @name.reference.class)
```

Tests will pin the expected tag set per fixture, so query changes are
visible in CI.

---

## 7. PageRank (hand-rolled)

Power iteration, no external deps. For N files:

```cpp
std::vector<double> pagerank(
    const std::vector<std::vector<std::pair<uint32_t,double>>>& adj,
    size_t n,
    double damping = 0.85,
    size_t iters = 50,
    double tol = 1e-6);
```

Iteration: `r' = d * A^T * r + (1-d)/N * 1`

Early exit when `||r' - r||_1 < tol`. Typical convergence: 20-30 iters on
2k-node graphs.

Sparse representation: `adj[src_file] = [(dst_file, weight), ...]`.
Normalize outbound edges per source before iteration.

Memory: O(edges). For 2k files with avg 30 refs each → 60k edges ≈ 1 MB.

---

## 8. Build system

### third_party/

Use git submodules pinned to tags, same as existing `tests/test_helper/`
submodules:

```
[submodule "third_party/tree-sitter"]
  path = third_party/tree-sitter
  url = https://github.com/tree-sitter/tree-sitter.git
[submodule "third_party/tree-sitter-typescript"]
  path = third_party/tree-sitter-typescript
  url = https://github.com/tree-sitter/tree-sitter-typescript.git
[submodule "third_party/tree-sitter-javascript"]
  path = third_party/tree-sitter-javascript
  url = https://github.com/tree-sitter/tree-sitter-javascript.git
```

Build as static libs (pure C). tree-sitter core has no external deps.
Grammar repos ship pre-generated `parser.c`; no `tree-sitter generate`
needed.

### CMake changes

New static lib `sg_repomap`:

```cmake
add_library(tree_sitter STATIC
  third_party/tree-sitter/lib/src/lib.c)
target_include_directories(tree_sitter PUBLIC
  third_party/tree-sitter/lib/include)

add_library(tree_sitter_typescript STATIC
  third_party/tree-sitter-typescript/typescript/src/parser.c
  third_party/tree-sitter-typescript/typescript/src/scanner.c)
# NOTE: tsx/src/ deliberately excluded in MVP; add in Phase 8

add_library(tree_sitter_javascript STATIC
  third_party/tree-sitter-javascript/src/parser.c
  third_party/tree-sitter-javascript/src/scanner.c)

add_library(sg_repomap STATIC
  src/native/repomap_parser.cpp
  src/native/repomap_index.cpp
  src/native/repomap_store.cpp
  src/native/repomap_format.cpp
  src/native/repomap_service.cpp
  src/native/policy_repomap.cpp)
target_link_libraries(sg_repomap PUBLIC
  tree_sitter tree_sitter_typescript tree_sitter_javascript)

# Link into daemon:
target_link_libraries(sgd PRIVATE sg_repomap)

# New CLI:
add_executable(asg-repomap src/tools/asg_repomap_main.cpp)
target_link_libraries(asg-repomap PRIVATE sg_common sg_repomap)
install(TARGETS asg-repomap RUNTIME DESTINATION bin)
```

Compile flags: `-O2 -march=znver4 -pipe -Wall -Wextra` (per global CLAUDE.md
— this is znver4 hardware).

### Binary size impact

Rough estimate: tree-sitter core ~200 KB, each grammar ~500 KB-2 MB (TS is
the heaviest grammar in the ecosystem). Total added to sgd: ~4-5 MB. Fine.

---

## 9. CLI — `asg-repomap`

```
asg-repomap build  [--root PATH] [--force]
asg-repomap update [--root PATH]
asg-repomap render [--root PATH] [--budget N]
asg-repomap query  [--root PATH] <ident>
asg-repomap stats  [--root PATH]
asg-repomap clean  [--root PATH]
```

- `--root` defaults to `git rev-parse --show-toplevel` or `$PWD`
- `render` is what session-start calls internally; CLI mirror for debugging
- `query` emits JSON with `{defines: [...], references: [...]}` for a
  symbol — useful for sanity checks
- `stats` prints file count, tag count, cache size, last-build time
- `clean` removes the repo's cache dir

No install action. Cache lives under `~/.claude/.safeguard/repomap/`.

---

## 10. Config (features.env + config.env)

```bash
# features.env
SG_REPOMAP_ENABLED=1            # 0 disables session-start injection
SG_REPOMAP_MAX_TOKENS=1024      # budget for additionalContext
SG_REPOMAP_ROOT_MODE=git        # git | cwd
SG_REPOMAP_MAX_FILE_BYTES=524288  # skip files > 512 KB
# Cache dir is always <repo_root>/.asg-repomap/ — not configurable in MVP.
```

Respected by both daemon (render-time) and CLI. `SG_*` prefix matches
existing convention.

### Ignore rules (MVP)

Hardcoded plus optional file:

- Always skip: `.git/`, `node_modules/`, `vendor/`, `build/`, `dist/`,
  `.next/`, `coverage/`, `__pycache__/`, `.venv/`, `target/`
- Respect `.gitignore` if present (simple glob match — no full gitignore
  parser in MVP; use git ls-files when in a repo)

`git ls-files` from cwd is the simplest correct path. Non-git repos fall
back to manual walk with the hardcoded skip list.

---

## 11. Protocol extension

Add a new daemon operation to the existing Unix-socket protocol:

### Request (client → daemon)

```json
{"op":"repomap_render","cwd":"/abs/path","budget":1024}
```

### Response (daemon → client)

```json
{"ok":true,"text":"...","tag_count":412,"file_count":187,"took_ms":42}
```

Error case:

```json
{"ok":false,"error":"parser_init_failed","detail":"..."}
```

Session-start hook client:
- Send request with 500 ms hard timeout
- On `ok:true`, emit SessionStart response with
  `additionalContext` = response.text
- On error or timeout, emit passthrough (empty additionalContext).
  Silently. Session must not block.

---

## 12. Testing (TDD — mandatory per CLAUDE.md)

Every phase lands tests first. No code merges without tests. Matches the
existing discipline in this repo.

### C++ unit tests (new)

Pick gtest or doctest. Doctest is single-header, fits the minimal
philosophy. Add `tests/native/` with:

- `test_repomap_parser.cpp` — given fixture files in
  `tests/fixtures/repomap/ts/`, parse and assert expected tag list
- `test_repomap_index.cpp` — build small synthetic graphs, assert PageRank
  values match hand-computed expectations within 1e-4
- `test_repomap_store.cpp` — write/read cache round-trip, mtime skip
- `test_repomap_format.cpp` — given tag list + budget, assert output is
  deterministic and fits budget

Fixtures:

```
tests/fixtures/repomap/
  ts-minimal/        # 3 files, hand-computed expected tags + ranks
  ts-crossref/       # a.ts defines, b.ts references — edge must exist
  js-minimal/
```

### bats integration tests (extending existing)

Add `tests/integration/repomap.bats`:

- `asg-repomap build` on fixture repo produces cache file
- `asg-repomap render --budget 200` emits non-empty output fitting budget
- `asg-repomap update` after touching one file reparses exactly that file
- `asg-repomap clean` removes cache dir

Extend `tests/integration/session_lifecycle.bats`:

- With `SG_REPOMAP_ENABLED=1` and a prebuilt cache, session-start response
  includes `additionalContext` containing expected tag lines
- With `SG_REPOMAP_ENABLED=0`, no `additionalContext` added
- With corrupt cache, session-start still succeeds (fail-soft path)
- With 500 ms daemon delay, session-start still succeeds (timeout path)

### CI

Update `.github/workflows/ci.yml`:
- `git submodule update --init --recursive` for tree-sitter submodules
- Cache the submodules between runs (they're pinned)
- Run new native tests + bats tests

---

## 13. Phases and milestones

Each phase ends with green tests + a working commit. No phase merges if
tests are red.

### Phase 0 — Foundation (goal: compile tree-sitter, parse one file)

- Add 4 submodules (doctest + tree-sitter + 2 grammars), CMake plumbing,
  link check
- `asg-repomap build` stub that just parses one file and prints node count
- Smoke test in bats

### Phase 1 — Parser + tags (goal: extract Tag[] from TS + JS)

- Port aider's `typescript-tags.scm` and `javascript-tags.scm`
- `repomap_parser.cpp` loads grammar, runs query, emits `vector<Tag>`
- Fixture tests with expected tag lists

### Phase 2 — Index + PageRank (goal: ranked file list)

- Build `defines` / `references` maps
- Edge weights with identifier shape heuristics
- Hand-rolled PageRank
- Fixture tests with hand-computed expected ranks

### Phase 3 — Formatter + budget (goal: bounded text output)

- `path:line kind name` rendering
- Binary search on `top_n` under token budget
- Deterministic ordering
- Tests

### Phase 4 — Cache (goal: incremental is sub-second)

- Write/read binary cache
- mtime-based skip on build
- `update` subcommand reparses only changed files
- Tests with timing assertions

### Phase 5 — Daemon integration (goal: session-start emits map)

- New protocol op `repomap_render`
- `policy_repomap` in daemon
- `session-start` hook client wires up the request, fail-soft path
- bats tests

### Phase 6 — Installer + config (goal: asg-install ships it)

- Install `asg-repomap` to `~/.local/bin`
- features.env defaults
- Uninstaller removes cache dir

### Phase 7 — Validation on real repos (goal: measure)

- Run on `~/src/fab`, `~/src/ronald`, `~/src/sau`
- Measure: build time, cache size, render time, `additionalContext` size
- Tune default `SG_REPOMAP_MAX_TOKENS`
- Write a `docs/repomap.md` with the numbers

### Phase 8 — Language expansion (not MVP)

- TSX (add `tree-sitter-typescript/tsx/src/` to the grammar lib +
  `tsx-tags.scm`)
- tree-sitter-pascal (for fab's Delphi legacy)
- tree-sitter-php
- tree-sitter-python
- Each new language = one `.scm` query + one fixture test

---

## 14. Locked decisions

All decisions locked with the user before coding. No more open questions
for Phase 0.

1. **C++ test framework: doctest**. Single-header, vendored under
   `third_party/doctest/doctest.h`. Matches the minimal-deps philosophy
   and the repo has no existing C++ test framework to clash with.

2. **Library split: new `sg_repomap` static lib**. Keeps tree-sitter and
   grammar code out of `sg_common`. `sg_common` stays grammar-free and
   safety-critical. `sgd` and `asg-repomap` link both.

3. **Cache location: per-repo at `<repo>/.asg-repomap/tags.v1.bin`**. On
   first build, add `.asg-repomap/` to `.git/info/exclude` (git-local,
   not `.gitignore` — we don't modify files the user commits). Non-git
   repos just get the dir with no ignore handling. Cache survives
   `~/.claude` wipes and lives with the code it describes.

4. **Token approximation: `chars / 4`** for MVP. Revisit in Phase 7 after
   measuring actual Claude Code tokenizer behavior on real repos.

5. **Session-start injection: `SG_REPOMAP_ENABLED=1` by default**. Tight
   budget (`SG_REPOMAP_MAX_TOKENS=1024`) so the map never dominates
   context. User can disable via features.env.

6. **Languages for Phase 1: TypeScript + JavaScript only**. No TSX in
   MVP. TSX lands in Phase 8 alongside PHP/Pascal/Python. Cuts one
   grammar build target and one `.scm` query file.

7. **Ignore rules: `git ls-files` when in a git repo**. Non-git repos
   fall back to the hardcoded skip list (`.git/`, `node_modules/`,
   `vendor/`, `build/`, `dist/`, `.next/`, `coverage/`, `__pycache__/`,
   `.venv/`, `target/`). No custom gitignore parser.

8. **Token budget: binary search on `top_n`** (aider's approach).
   Matches the reference implementation; easier to reason about than
   proportional allocation.

---

## 15. Out of scope (explicit)

- Windows/macOS support — Linux-first per asg's own roadmap
- Watch mode / inotify-based live update — session-start + incremental on
  demand is enough; watch adds a daemon thread + complexity
- HTTP or MCP surface — this is stdio-over-Unix-socket only
- Shipping a package catalog extension — repomap is a built-in, not a
  catalog package
- Multi-repo registry — one index per `--root`; users invoke per project
- Semantic/embedding search — out of the "minimal port" spirit
- Auto-run on every tool use — only session-start and explicit CLI

---

## 16. Ready-to-execute checklist (for the next session)

When a fresh session starts from this file:

1. [ ] Re-read `CLAUDE.md` + `native/README.md` + `docs/rule-engine-architecture.md`
2. [ ] Confirm the locked decisions in section 14 are still wanted (should
       be fast — user already signed off)
3. [ ] Phase 0: add submodules, CMake wiring, compile, smoke test
4. [ ] Phase 1: parser + tags (tests first)
5. [ ] Phase 2: index + PageRank (tests first)
6. [ ] Phase 3: formatter + budget (tests first)
7. [ ] Phase 4: cache (tests first)
8. [ ] Phase 5: daemon integration (tests first)
9. [ ] Phase 6: installer + config
10. [ ] Phase 7: run on `~/src/fab`, `~/src/ronald`, `~/src/sau`, record
    numbers in `docs/repomap.md`

Each phase ends with `make test` green and a single commit.
