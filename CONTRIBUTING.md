# Contributing to agent-safe-guard

## Development Setup

```bash
git clone https://github.com/regen-dev/agent-safe-guard.git
cd agent-safe-guard
git submodule update --init --recursive
cmake -S . -B build/native -DSG_BUILD_NATIVE=ON
cmake --build build/native -j$(nproc)
```

## Requirements

- Linux (x86_64)
- CMake 3.20+
- C++20 compiler (g++ 10+ or clang++ 13+)
- jq
- bats-core 1.11+ (included as git submodule)

## Test-Driven Development

This project follows strict TDD. Every code change requires a test.

1. Write a failing test first
2. Write the minimum code to make it pass
3. Refactor if needed, keeping tests green
4. Run `make test` before submitting

```bash
make test                    # All tests
make test-native-pre-smoke   # Pre-tool-use smoke tests
make test-native-rule-audit  # Rule compilation audit
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Write tests for your change
4. Ensure `make test` passes
5. Keep commits focused and well-described
6. Open a PR against `main`

## Code Style

- C++20 with no external dependencies beyond the standard library
- Function prefix: `_sg_*` for internal functions
- Env var prefix: `SG_*`
- Hook launcher prefix: `asg-*`

## Adding Rules

Built-in rules live in the native daemon source. Extension rules go in the [catalog repo](https://github.com/regen-dev/agent-safe-guard-rules).

Every new rule must have a bats test proving it blocks or allows the expected input.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
