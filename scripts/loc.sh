#!/usr/bin/env bash
# Count Rust lines: shipped source (src/, excluding in-file #[cfg(test)] modules and
# src/noise/tests.rs) versus test code (those modules plus tests/ and benches/).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"
src_total=0
src_test=0
for f in $(find src -name '*.rs' | sort); do
  n=$(wc -l <"$f")
  if [ "$f" = "src/noise/tests.rs" ]; then
    t=$n
  else
    # In this crate every #[cfg(test)] module runs to the end of its file.
    start=$(grep -n '^#\[cfg(test)\]$' "$f" | tail -1 | cut -d: -f1 || true)
    if [ -n "${start}" ] && sed -n "$((start + 1))p" "$f" | grep -q '^mod tests'; then
      t=$((n - start + 1))
    else
      t=0
    fi
  fi
  src_total=$((src_total + n))
  src_test=$((src_test + t))
done
ext=$(cat tests/*.rs benches/*.rs | wc -l)
echo "shipped source lines (src/, non-test): $((src_total - src_test))"
echo "test lines (in-file unit tests):        ${src_test}"
echo "test lines (tests/ + benches/):         $((ext))"
