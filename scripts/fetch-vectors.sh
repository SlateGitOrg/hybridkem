#!/usr/bin/env bash
# Download the pinned NIST ACVP ML-KEM (FIPS 203) and X-Wing draft vector files and verify
# their SHA-256.
#
# The files are also committed under vectors/ so `make check` works offline; this script
# exists to prove provenance: it re-downloads from the pinned upstream commits and fails if a
# single byte differs from the checksums in vectors/SHA256SUMS.
#
# Usage: scripts/fetch-vectors.sh [--verify-only]
set -euo pipefail

ACVP_COMMIT="ad33b3d9504491767f1aa76382464f3b3fa2359e"
ACVP_BASE="https://raw.githubusercontent.com/usnistgov/ACVP-Server/${ACVP_COMMIT}/gen-val/json-files"
# X-Wing (draft-connolly-cfrg-xwing-kem-06) vectors from the draft's own repository.
XWING_COMMIT="5cb311dc7c7761c2b82d2f4a0037da2c2c7af8f3"
XWING_URL="https://raw.githubusercontent.com/dconnolly/draft-connolly-cfrg-xwing-kem/${XWING_COMMIT}/spec/test-vectors.json"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUMS="${ROOT}/vectors/SHA256SUMS"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify() {
  local status=0
  while read -r want name; do
    [ -z "${want}" ] && continue
    local got
    got="$(sha256 "${ROOT}/vectors/${name}")"
    if [ "${got}" = "${want}" ]; then
      echo "ok       ${name}"
    else
      echo "MISMATCH ${name}: want ${want} got ${got}" >&2
      status=1
    fi
  done <"${SUMS}"
  return "${status}"
}

fetch() {
  local url="$1" dst="$2"
  echo "fetch    ${url} -> vectors/${dst}"
  mkdir -p "$(dirname "${ROOT}/vectors/${dst}")"
  curl --fail --silent --show-error --location "${url}" -o "${ROOT}/vectors/${dst}.tmp"
  mv "${ROOT}/vectors/${dst}.tmp" "${ROOT}/vectors/${dst}"
}

if [ "${1:-}" = "--verify-only" ]; then
  verify
  exit $?
fi

fetch "${ACVP_BASE}/ML-KEM-keyGen-FIPS203/internalProjection.json" "acvp/keygen.json"
fetch "${ACVP_BASE}/ML-KEM-encapDecap-FIPS203/internalProjection.json" "acvp/encap-decap.json"
fetch "${XWING_URL}" "xwing/test-vectors.json"
verify
