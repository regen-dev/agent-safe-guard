# Changelog

## 1.0.0 (2026-05-01)


### Features

* add release pipeline and improve GitHub discoverability ([a8a5b46](https://github.com/regen-dev/agent-safe-guard/commit/a8a5b466033bb7c9a18a6302073e1d29deb4c4e9))
* **asg-cli:** surface Repomap in the Settings tab ([0104d75](https://github.com/regen-dev/agent-safe-guard/commit/0104d75f7242bc79e803489cf42a88158efcddbe))
* **daemon:** add RSS watchdog and systemd memory limits ([7dfa938](https://github.com/regen-dev/agent-safe-guard/commit/7dfa9389ebc07bda217793f78008fdd7fa7eb4f3))
* **repomap:** bound PageRank work per identifier and add deadline ([4019fb2](https://github.com/regen-dev/agent-safe-guard/commit/4019fb2c9f5afbd4a0895927796346d5b312e965))
* **repomap:** Phase 0 — tree-sitter scaffold + asg-repomap parse stub ([fe784d2](https://github.com/regen-dev/agent-safe-guard/commit/fe784d2263e5c7f52627f58a341263bbdb808c8c))
* **repomap:** Phase 1 — tag extraction via tree-sitter queries ([c8f7228](https://github.com/regen-dev/agent-safe-guard/commit/c8f72288048d7bdb4f4d7ca38862cf9b97c9edcb))
* **repomap:** Phase 2 — filesystem index + PageRank ranker ([1b66879](https://github.com/regen-dev/agent-safe-guard/commit/1b66879ace5ca4dd612d79d179f375e72b23f6dc))
* **repomap:** Phase 3 — formatter + token budget ([2308bbd](https://github.com/regen-dev/agent-safe-guard/commit/2308bbd9d8eb4b152e2d83dbb0ed31f1f810dce9))
* **repomap:** Phase 4 — binary cache with mtime-based incremental ([ff030c9](https://github.com/regen-dev/agent-safe-guard/commit/ff030c9541fe3d8f327ce67da419c762b6e7dac7))
* **repomap:** Phase 5 — session-start injects additionalContext ([475c1b5](https://github.com/regen-dev/agent-safe-guard/commit/475c1b53e66ff6c4cc10f9fa7d2e26ed7c026045))
* **repomap:** Phase 6 — installer + features.env defaults ([8e977b8](https://github.com/regen-dev/agent-safe-guard/commit/8e977b8078e4a8c85afb93860823b84f2d58aa0b))
* **repomap:** Phase 7 — validation, tuning, and docs ([6311286](https://github.com/regen-dev/agent-safe-guard/commit/6311286844f974ed3ac3f3f3281f77dbf6c2b115))
* **repomap:** refuse unsafe roots and cap source-file walks ([0146c17](https://github.com/regen-dev/agent-safe-guard/commit/0146c1734af1facab1247b6b4d2b0af982632859))


### Bug Fixes

* **read-defense:** skip minified-file rules when command filters them out ([0e11c41](https://github.com/regen-dev/agent-safe-guard/commit/0e11c41ddc60c9b326c386888da64921992a64fa))
* repair 6 CI test failures and switch to native-only test pipeline ([376915e](https://github.com/regen-dev/agent-safe-guard/commit/376915e32d4595aaac3ee43fc331a1cba1340f06))
* **repomap:** skip .vscode / .idea / .history from the repo walk ([ef0d981](https://github.com/regen-dev/agent-safe-guard/commit/ef0d981e31a4787fa80463c3daf6ff1bdb03198c))
