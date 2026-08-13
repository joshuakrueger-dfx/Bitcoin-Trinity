#!/usr/bin/env bash
# Recompute Trinity extract entropy from raw_csprng + extra_bytes.
#
# Spec §2.2 / D13 / S20: an external tool must reproduce
#
#     entropy := HMAC-SHA512(key = raw_csprng, msg = extra_bytes)[0..L]
#
# using literally `openssl dgst -sha512` (HMAC via `-mac HMAC -macopt hexkey:`).
# This is the verification-sheet offline path.
#
# Usage:
#   scripts/recompute_entropy.sh <raw_csprng_hex> <extra_bytes_hex> <L>
#
#   raw_csprng_hex   64 hex characters (32 bytes). Case-insensitive.
#   extra_bytes_hex  even-length hex, or empty / "-" for no additional source.
#   L                16 (12 words) or 32 (24 words).
#
# Prints the first L bytes of the HMAC as lowercase hex on stdout.
# Fail-closed: any malformed input exits 1 with a message on stderr.
#
#   set -euo pipefail
# Implements WP-30; requirements in docs/SPECIFICATION.md §2.2, §2.2.4, D13, S20.

set -euo pipefail

fail() { printf '%s\n' "$*" >&2; exit 1; }

if [[ $# -ne 3 ]]; then
  fail "usage: $0 <raw_csprng_hex> <extra_bytes_hex> <L>"
fi

raw_hex="$1"
extra_hex="$2"
l="$3"

if [[ "$extra_hex" == "-" ]]; then
  extra_hex=""
fi

if [[ ! "$raw_hex" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  fail "raw_csprng_hex must be exactly 64 hex characters"
fi

if [[ -n "$extra_hex" && ! "$extra_hex" =~ ^([0-9A-Fa-f]{2})+$ ]]; then
  fail "extra_bytes_hex must be even-length hex or empty"
fi

if [[ "$l" != "16" && "$l" != "32" ]]; then
  fail "L must be 16 or 32"
fi

# HMAC-SHA512 with a binary key given as hex. Empty extra_bytes is a zero-length
# message (Spec §2.2.2: extract = HMAC-SHA512(raw_csprng, "")).
#
# The binary digest is never stored in a shell variable: bash command
# substitution strips NUL bytes, which would silently corrupt the hex.
printf '%s' "$extra_hex" | xxd -r -p \
  | openssl dgst -sha512 -mac HMAC -macopt "hexkey:${raw_hex}" -binary \
  | head -c "$l" \
  | xxd -p -c 256 \
  | tr -d '\n' \
  | tr 'A-F' 'a-f'
printf '\n'
