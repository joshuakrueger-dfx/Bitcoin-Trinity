# BTC Trinity — Aufgaben. Siehe docs/TESTING.md.

default:
    @just --list

# --- Prüfungen, die in CI bei jedem Push laufen ---

check: fmt-check clippy build check-plan dep-budget
    @echo "✓ Schneller Pfad grün"

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

# Konsistenz der vier Dokumente gegeneinander (TESTING.md §6)
check-plan:
    python3 scripts/check_plan.py

# Abhängigkeitsbudget im Signaturpfad (SPECIFICATION.md §1.7)
dep-budget:
    python3 scripts/dep_budget.py

deny:
    cargo deny check

audit:
    cargo audit

# --- Testumgebung (WP-02) ---

test-env-up:
    ./scripts/test-env.sh up

test-env-down:
    ./scripts/test-env.sh down

test-env-reset:
    ./scripts/test-env.sh reset

# --- Schwere Läufe ---

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
