# Packaging Implementation Plan

Concrete implementation steps for Phases 2-4 of the [distribution roadmap](distribution-roadmap.md).

## Binary Inventory

| Type | Binaries | Count |
|------|----------|-------|
| Daemon | `sgd` | 1 |
| Hook clients | `sg-hook-{pre-tool-use,post-tool-use,permission-request,read-guard,read-compress,stop,session-start,session-end,pre-compact,subagent-start,subagent-stop,tool-error}` | 12 |
| User tools | `asg-cli`, `asg-statusline`, `asg-install`, `asg-uninstall` | 4 |
| systemd units | `sgd.service`, `sgd.socket` | 2 |
| **Total binaries** | | **17** |

## Step 0: Prerequisites

### 0.1 Fix `asg-install` source-tree dependency

**Problem:** `asg-install` is compiled with `SG_SOURCE_ROOT="${CMAKE_SOURCE_DIR}"`. This hardcodes the build machine path, which does not exist on a user's system after package install.

**Fix:** Replace `SG_SOURCE_ROOT` with runtime binary discovery:

- Resolve own path via `/proc/self/exe` (Linux) or `argv[0]` realpath
- Derive the lib directory as `<exe_dir>/../lib/agent-safe-guard/` (FHS layout) or fall back to `<exe_dir>/` (flat build tree)
- Accept `SG_LIBDIR` env var as explicit override for non-standard layouts
- Remove `SG_SOURCE_ROOT` compile definition from CMake

**Blocks:** everything else

### 0.2 Complete CMake install rules

Current state: single `install(TARGETS ... RUNTIME DESTINATION bin)` puts all 17 binaries in `bin/`.

Target FHS layout:

```
/usr/bin/                              asg-cli, asg-install, asg-uninstall, asg-statusline
/usr/lib/agent-safe-guard/             sgd, sg-hook-*
/usr/lib/systemd/user/                 sgd.service, sgd.socket
/usr/share/doc/agent-safe-guard/       README.md, LICENSE
```

Changes needed in `native/CMakeLists.txt`:

- Split install into two groups: user-facing tools to `bin`, internal binaries to `lib/agent-safe-guard`
- Add `install(FILES ...)` for systemd units and docs
- Update `sgd.service` `ExecStart=` to point to `/usr/lib/agent-safe-guard/sgd`

**Blocks:** .deb, AppImage

## Step 1: Debian Package via CPack

### 1.1 CPack configuration

Add to root `CMakeLists.txt`:

```cmake
project(agent_safe_guard VERSION 0.1.0 LANGUAGES CXX)

# ... existing content ...

set(CPACK_GENERATOR "DEB")
set(CPACK_DEBIAN_PACKAGE_NAME "agent-safe-guard")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "jq")
set(CPACK_DEBIAN_PACKAGE_SECTION "utils")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "Safety hook system for Claude Code")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "regen-dev")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/regen-dev/agent-safe-guard")
set(CPACK_PACKAGE_FILE_NAME "agent-safe-guard_${PROJECT_VERSION}_amd64")
include(CPack)
```

### 1.2 Package scripts (minimal)

- `postinst`: print activation instructions ("run `asg-install` to activate hooks")
- `prerm`: no-op (do not touch `~/.claude/`)
- `postrm`: only remove `/usr/lib/agent-safe-guard/` on purge, never touch user state

### 1.3 Local test

```bash
cmake -S . -B build/pkg -DSG_BUILD_NATIVE=ON -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build/pkg -j
cd build/pkg && cpack -G DEB && cd ../..

# Validate in clean container
docker run --rm -v ./build/pkg:/pkg ubuntu:24.04 bash -c \
  "apt-get update && dpkg -i /pkg/*.deb || apt-get install -fy && \
   asg-install --dry-run && asg-cli --help && which sgd && \
   dpkg -r agent-safe-guard"
```

### 1.4 Validation checklist

- [ ] `dpkg -i` installs without errors
- [ ] `asg-install --dry-run` works (finds binaries without source tree)
- [ ] `asg-cli --help` works
- [ ] `sgd` is in `/usr/lib/agent-safe-guard/`
- [ ] `asg-cli` is in `/usr/bin/`
- [ ] systemd units in `/usr/lib/systemd/user/`
- [ ] `dpkg -r` removes cleanly, does not touch `~/.claude/`
- [ ] `dpkg --purge` removes `/usr/lib/agent-safe-guard/`

## Step 2: AppImage

### 2.1 Build script `scripts/build-appimage.sh`

Steps:

1. `cmake --install build/pkg --prefix AppDir/usr`
2. Create `AppDir/AppRun` (multi-command dispatcher via `argv[0]` or first argument)
3. Create `.desktop` file (Category=Utility, Terminal=true)
4. Provide placeholder icon
5. Run `linuxdeploy --appdir AppDir --output appimage`

### 2.2 AppRun multi-command dispatch

The AppImage bundles all 17 binaries. `AppRun` dispatches based on:

- Symlink name: if user creates `ln -s agent-safe-guard.AppImage asg-cli`, runs `asg-cli`
- First argument: `./agent-safe-guard.AppImage asg-cli --help`
- No argument: print usage listing available commands

### 2.3 Local test

```bash
./scripts/build-appimage.sh
./agent-safe-guard-x86_64.AppImage asg-install --dry-run
./agent-safe-guard-x86_64.AppImage asg-cli --help
./agent-safe-guard-x86_64.AppImage sgd --help
```

### 2.4 Open question: daemon lifecycle

When running from AppImage, `sgd` lives inside the FUSE mount. Options:

- **A)** Run `sgd` directly from mount (simpler, but mount must stay active)
- **B)** `asg-install` copies `sgd` + hooks to `~/.local/lib/agent-safe-guard/` (works without mount)

Recommendation: start with A, revisit if users report issues.

## Step 3: GitHub Actions Release Workflow

### 3.1 Workflow file `.github/workflows/release.yml`

```yaml
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write

jobs:
  build-release:
    runs-on: ubuntu-24.04
    timeout-minutes: 30

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          submodules: recursive

      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y jq cmake g++ make file

      - name: Configure
        run: cmake -S . -B build/pkg -DSG_BUILD_NATIVE=ON -DCMAKE_INSTALL_PREFIX=/usr

      - name: Build
        run: cmake --build build/pkg -j2

      - name: Test suite
        run: make test

      - name: Native smoke tests
        run: make test-native-pre-smoke

      - name: Build .deb
        run: cd build/pkg && cpack -G DEB

      - name: Install linuxdeploy
        run: |
          curl -fsSL -o linuxdeploy https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
          chmod +x linuxdeploy
          sudo mv linuxdeploy /usr/local/bin/

      - name: Build AppImage
        run: ./scripts/build-appimage.sh

      - name: Generate checksums
        run: |
          sha256sum build/pkg/*.deb *.AppImage > checksums-sha256.txt

      - name: Create release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release create "${{ github.ref_name }}" \
            build/pkg/*.deb \
            *.AppImage \
            checksums-sha256.txt \
            --generate-notes
```

### 3.2 Release workflow

```
git tag v0.1.0
git push origin v0.1.0
# GitHub Actions builds, tests, packages, publishes
```

### 3.3 Security considerations

- CI workflow uses `permissions: contents: write` only on tag push (not on PRs)
- SHA256 checksums published with every release
- Future: add `cosign` signing via sigstore (not blocking v0.1)
- Future: add SBOM generation for supply chain transparency

## Execution Order and Dependencies

```
0.1 Fix asg-install ─────┐
                          ├─→ 1.1 CPack config ──→ 1.3 Local .deb test ─┐
0.2 CMake install rules ──┘                                               │
                          └─→ 2.1 AppImage script ─→ 2.3 Local test ────┤
                                                                         │
                                                      3.1 release.yml ←──┘
                                                             │
                                                      3.2 Tag v0.1.0
```

## Decisions Pending

| # | Question | Recommendation | Status |
|---|----------|----------------|--------|
| 1 | Single package or split (`agent-safe-guard` + `agent-safe-guard-daemon`)? | Single package for v0.1, split later if needed | pending |
| 2 | systemd user units: enable on install or keep in `asg-install`? | Keep in `asg-install` (package only installs templates) | pending |
| 3 | Version source: `project(VERSION)` or git tag? | `project(VERSION)` as source of truth, CI validates tag matches | pending |
| 4 | Artifact signing with cosign in v0.1? | Defer to v0.2, ship checksums only in v0.1 | pending |
| 5 | AppImage daemon lifecycle: run from mount or copy out? | Run from mount (option A) for v0.1 | pending |
