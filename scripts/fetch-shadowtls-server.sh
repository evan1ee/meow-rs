#!/usr/bin/env bash
# Official ShadowTLS server (ihciah/shadow-tls) — test-only interop peer for
# `crates/meow-proxy/tests/shadow_tls_v3_e2e.rs`. Pinned release + SHA-256.
set -euo pipefail

destination="${1:?usage: fetch-shadowtls-server.sh <output-directory>}"
version="0.2.25"
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    asset="shadow-tls-x86_64-unknown-linux-musl"
    checksum="a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532"
    ;;
  Linux:aarch64|Linux:arm64)
    asset="shadow-tls-aarch64-unknown-linux-musl"
    checksum="3295476b37f549a68906519d3eaecb74bf3b6eaf9094cebb16ee84f0151373c6"
    ;;
  Darwin:x86_64)
    asset="shadow-tls-x86_64-apple-darwin"
    checksum="ce88d1283e745db51f621e2403dcfdec2e128151f729fcaefc2a319f11368b2b"
    ;;
  Darwin:arm64)
    asset="shadow-tls-aarch64-apple-darwin"
    checksum="a7c39d70cfc5868f654b19766b768518413ac4ffd9532ea8534a36a1d447b5b1"
    ;;
  *) printf 'Unsupported shadow-tls test platform\n' >&2; exit 1 ;;
esac

temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT
curl --fail --location --retry 3 --retry-all-errors --connect-timeout 15 --max-time 180 \
  --proto '=https' --tlsv1.2 \
  "https://github.com/ihciah/shadow-tls/releases/download/v${version}/${asset}" \
  --output "$temporary/$asset"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$temporary/$asset" | cut -d ' ' -f 1)"
else
  actual="$(shasum -a 256 "$temporary/$asset" | cut -d ' ' -f 1)"
fi
test "$actual" = "$checksum" || { printf 'shadow-tls binary SHA256 mismatch\n' >&2; exit 1; }
mkdir -p "$destination"
cp "$temporary/$asset" "$destination/shadow-tls"
chmod +x "$destination/shadow-tls"
printf 'Official shadow-tls v%s (%s), SHA256 verified\n' "$version" "$asset"
