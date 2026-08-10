#!/usr/bin/env bash
# Testumgebung: Bitcoin Core 30.2 (Regtest) mit blockfilterindex/peerblockfilters
# (CBF auf demselben Node), electrs. Signet-Node und separater CBF-Peer sind
# Abnahmeziele von WP-02 und stehen heute noch nicht in docker/compose.yml.
# Umsetzung von WP-02, Anforderungen in docs/TESTING.md §2.
#
#   ./scripts/test-env.sh up | down | reset | status
#
# Deterministisch: gleicher Startzustand bei jedem Lauf. Ohne das sind
# Differential-Tests nicht reproduzierbar und ein Fehlschlag nicht einordenbar.

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
  else fail "Weder 'docker compose' noch 'docker-compose' gefunden."
  fi
}

cli() { compose exec -T bitcoind bitcoin-cli -regtest \
          -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASS" "$@"; }

# Bitcoin Core 30.0 und 30.1 konnten beim Migrieren einer unbenannten
# Legacy-Wallet in einem Custom-Verzeichnis bei aktiviertem Pruning ALLE
# Wallet-Dateien des Knotens löschen; die Binaries wurden am 2026-01-05
# zurückgezogen (SPECIFICATION.md §0.3). Harter Abbruch, keine Warnung.
verify_core_version() {
  local raw major minor
  raw=$(cli getnetworkinfo | grep -o '"version":[[:space:]]*[0-9]*' | grep -o '[0-9]*$')
  major=$(( raw / 10000 ))
  minor=$(( (raw / 100) % 100 ))
  log "Bitcoin Core meldet ${major}.${minor} (subversion ${raw})"
  if [[ "$major" -eq 30 && ( "$minor" -eq 0 || "$minor" -eq 1 ) ]]; then
    fail "Bitcoin Core ${major}.${minor} ist verboten — Wallet-Migrations-Bug, Binaries zurückgezogen.
    Erwartet: ${CORE_VERSION} oder neuer. Siehe docs/TESTING.md §2.2."
  fi
  if [[ "$major" -lt 30 ]]; then
    fail "Bitcoin Core ${major}.${minor} ist zu alt. Erwartet: ${CORE_VERSION} oder neuer."
  fi
  ok "Core-Version zulässig"
}

wait_for_rpc() {
  log "Warte auf RPC …"
  for _ in $(seq 1 60); do
    if cli getblockchaininfo >/dev/null 2>&1; then ok "RPC erreichbar"; return 0; fi
    sleep 1
  done
  fail "RPC nach 60 s nicht erreichbar. Logs: docker compose -f '$COMPOSE_FILE' logs bitcoind"
}

# Fester Startzustand: 101 Blöcke, damit genau eine Coinbase reif ist.
seed_regtest() {
  log "Regtest-Startzustand herstellen …"
  cli createwallet "miner" false false "" false true true >/dev/null 2>&1 || true
  local addr
  addr=$(cli -rpcwallet=miner getnewaddress)
  cli generatetoaddress 101 "$addr" >/dev/null
  local h bal
  h=$(cli getblockcount)
  bal=$(cli -rpcwallet=miner getbalance)
  [[ "$h" -eq 101 ]] || fail "Erwartet 101 Blöcke, bekommen $h — Zustand nicht deterministisch."
  ok "101 Blöcke, Miner-Wallet mit ${bal} BTC"
}

cmd_up() {
  [[ -f "$COMPOSE_FILE" ]] || fail "docker/compose.yml fehlt."
  log "Starte Testumgebung (Core ${CORE_VERSION} Regtest inkl. Filter-Indizes, electrs) …"
  compose up -d
  wait_for_rpc
  verify_core_version
  seed_regtest
  ok "Bereit. RPC: http://${RPC_USER}:${RPC_PASS}@127.0.0.1:${RPC_PORT}"
}

cmd_down() {
  log "Räume auf (inkl. Volumes — der nächste Start ist wieder deterministisch) …"
  compose down -v --remove-orphans
  ok "Abgeräumt"
}

cmd_status() {
  compose ps
  cli getblockchaininfo 2>/dev/null | head -12 || echo "(bitcoind antwortet nicht)"
}

case "${1:-}" in
  up)     cmd_up ;;
  down)   cmd_down ;;
  reset)  cmd_down; cmd_up ;;
  status) cmd_status ;;
  *)      echo "Aufruf: $0 {up|down|reset|status}" >&2; exit 2 ;;
esac
