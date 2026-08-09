#!/usr/bin/env bash
# Test environment: Bitcoin Core 30.2 (regtest) with blockfilterindex/peerblockfilters
# (CBF on the same node), electrs. Signet node and a separate CBF peer are
# acceptance goals of WP-02 and are not yet in docker/compose.yml today.
# Implements WP-02; requirements in docs/TESTING.md §2.
#
#   ./scripts/test-env.sh up | down | reset | status
#
# Deterministic: same starting state on every run. Without that,
# differential tests are not reproducible and a failure is not interpretable.

set -euo pipefail

readonly CORE_VERSION="30.2"
readonly COMPOSE_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/docker/compose.yml"
readonly RPC_USER="trinity"
readonly RPC_PASS="regtest"
readonly RPC_PORT="18443"

log()  { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✗\033[0m %s\n' "$*" >&2; exit 1; }
ok()   { printf '\033[1;32m✓\033[0m %s\n' "$*"; }

compose() {
  if docker compose version >/dev/null 2>&1; then docker compose -f "$COMPOSE_FILE" "$@"
  elif command -v docker-compose >/dev/null 2>&1; then docker-compose -f "$COMPOSE_FILE" "$@"
  else fail "Neither 'docker compose' nor 'docker-compose' found."
  fi
}

cli() { compose exec -T bitcoind bitcoin-cli -regtest \
          -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" "$@"; }

# Bitcoin Core 30.0 and 30.1 could, when migrating an unnamed
# legacy wallet in a custom directory with pruning enabled, delete ALL
# wallet files of the node; the binaries were withdrawn on 2026-01-05
# (SPECIFICATION.md §0.3). Hard abort, not a warning.
verify_core_version() {
  local raw major minor
  raw=$(cli getnetworkinfo | grep -o '"version":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
  major=$(( raw / 10000 ))
  minor=$(( (raw / 100) % 100 ))
  log "Bitcoin Core reports ${major}.${minor} (subversion ${raw})"
  if [[ "$major" -eq 30 && ( "$minor" -eq 0 || "$minor" -eq 1 ) ]]; then
    fail "Bitcoin Core ${major}.${minor} is forbidden — wallet migration bug, binaries withdrawn.
    Expected: ${CORE_VERSION} or newer. See docs/TESTING.md §2.2."
  fi
  if [[ "$major" -lt 30 ]]; then
    fail "Bitcoin Core ${major}.${minor} is too old. Expected: ${CORE_VERSION} or newer."
  fi
  ok "Core version allowed"
}

wait_for_rpc() {
  log "Waiting for RPC …"
  for _ in $(seq 1 60); do
    if cli getblockchaininfo >/dev/null 2>&1; then ok "RPC reachable"; return 0; fi
    sleep 1
  done
  fail "RPC not reachable after 60 s. Logs: docker compose -f '$COMPOSE_FILE' logs bitcoind"
}

# Fixed starting state: 101 blocks so exactly one coinbase is mature.
seed_regtest() {
  log "Establishing regtest starting state …"
  cli createwallet "miner" false false "" false true true >/dev/null 2>&1 || true
  local addr
  addr=$(cli -rpcwallet=miner getnewaddress)
  cli generatetoaddress 101 "$addr" >/dev/null
  local h bal
  h=$(cli getblockcount)
  bal=$(cli -rpcwallet=miner getbalance)
  [[ "$h" -eq 101 ]] || fail "Expected 101 blocks, got $h — state not deterministic."
  ok "101 blocks, miner wallet with ${bal} BTC"
}

cmd_up() {
  [[ -f "$COMPOSE_FILE" ]] || fail "docker/compose.yml missing."
  log "Starting test environment (Core ${CORE_VERSION} regtest incl. filter indexes, electrs) …"
  compose up -d
  wait_for_rpc
  verify_core_version
  seed_regtest
  ok "Ready. RPC: http://${RPC_USER}:${RPC_PASS}@127.0.0.1:${RPC_PORT}"
}

cmd_down() {
  log "Cleaning up (incl. volumes — the next start is deterministic again) …"
  compose down -v --remove-orphans
  ok "Cleaned up"
}

cmd_status() {
  compose ps
  cli getblockchaininfo 2>/dev/null | head -12 || echo "(bitcoind not responding)"
}

case "${1:-}" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  reset)  cmd_down; cmd_up ;;
  status) cmd_status ;;
  *)      echo "Usage: $0 {up|down|reset|status}" >&2; exit 2 ;;
esac
