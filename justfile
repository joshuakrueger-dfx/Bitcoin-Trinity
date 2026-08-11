# BTC Trinity — tasks. See docs/TESTING.md.

default:
    @just --list

# --- Checks that run in CI on every push ---

check: fmt-check clippy build gate-tests check-plan dep-budget
    @echo "✓ Fast path green"

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

build:
    cargo build --workspace --locked

test:
    cargo test --workspace --locked

# Stdlib gate tests: workflow invariants, plan inventory, dep budget, compose binds
gate-tests:
    python3 -m unittest discover -s scripts/tests -p 'test_*.py'

# Consistency of the four documents against each other (TESTING.md §6)
check-plan:
    python3 scripts/check_plan.py

# Dependency budget on the signature path (SPECIFICATION.md §1.7)
dep-budget:
    python3 scripts/dep_budget.py

deny:
    cargo deny check

audit:
    cargo audit

# --- Test environment (WP-02) ---

test-env-up:
    ./scripts/test-env.sh up

test-env-down:
    ./scripts/test-env.sh down

test-env-reset:
    ./scripts/test-env.sh reset

# --- Heavy runs ---

diff-test:
    cargo test --workspace --locked --features differential -- --test-threads=1

signet-test:
    cargo test --workspace --locked --features signet -- --test-threads=1 --ignored

coverage:
    cargo llvm-cov --workspace --lcov --output-path lcov.info
    python3 scripts/coverage_gate.py lcov.info

mutants:
    cargo mutants -p trinity-verify -p trinity-signer -p trinity-keystore -p trinity-entropy

fuzz target:
    cargo fuzz run {{target}} -- -max_total_time=3600
