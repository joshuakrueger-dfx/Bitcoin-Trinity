#!/usr/bin/env bash
# Test environment: Bitcoin Core 30.2 (regtest) with blockfilterindex/peerblockfilters
# (CBF-capable on the same node via COMPACT_FILTERS), electrs.
# Signet is an optional later extension (not required by WP-02 acceptance).
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

# electrs must be running, not merely created — a bad cookie flag previously
# left the container Exited(1) while the script still reported Ready.
# Note: `compose ps -q` lists only running containers; use -a to see exits.
wait_for_electrs() {
  log "Waiting for electrs …"
  local id status
  for _ in $(seq 1 60); do
    id=$(compose ps -aq electrs 2>/dev/null || true)
    if [[ -n "$id" ]]; then
      status=$(docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null || true)
      if [[ "$status" == "exited" || "$status" == "dead" ]]; then
        compose logs --tail=40 electrs || true
        fail "electrs container is ${status}. Logs above. Fix docker/compose.yml electrs args."
      fi
      if [[ "$status" == "running" ]]; then
        if command -v nc >/dev/null 2>&1 && nc -z 127.0.0.1 60401 2>/dev/null; then
          ok "electrs running (TCP 127.0.0.1:60401)"
          return 0
        fi
        # bash /dev/tcp fallback when nc is absent
        if (echo >/dev/tcp/127.0.0.1/60401) >/dev/null 2>&1; then
          ok "electrs running (TCP 127.0.0.1:60401)"
          return 0
        fi
      fi
    fi
    sleep 1
  done
  compose logs --tail=40 electrs || true
  compose ps -a electrs || true
  fail "electrs not ready after 60 s."
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
  # Funded means spendable coinbase maturity (50 BTC after 101 blocks).
  awk -v b="$bal" 'BEGIN { exit !(b+0 > 0) }' \
    || fail "Expected funded miner wallet (balance > 0), got ${bal}"
  ok "101 blocks, miner wallet with ${bal} BTC"
}

cmd_up() {
  [[ -f "$COMPOSE_FILE" ]] || fail "docker/compose.yml missing."
  log "Starting test environment (Core ${CORE_VERSION} regtest incl. filter indexes, electrs) …"
  compose up -d
  wait_for_rpc
  verify_core_version
  seed_regtest
  wait_for_electrs
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
