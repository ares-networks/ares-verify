#!/usr/bin/env bash
# Fails if any tracked file matches a forbidden pattern.
#
# This repository is meant to be published. The patterns (names that must not
# appear in it) are deliberately NOT stored here, since listing them would
# publish them: CI supplies them in PUBLIC_GATE_PATTERN (an extended regex,
# case-insensitive), held as a secured pipeline variable. Unset means skip,
# loudly; set REQUIRE_PUBLIC_GATE=1 to make unset a failure (release builds).
set -euo pipefail

if [[ -z "${PUBLIC_GATE_PATTERN:-}" ]]; then
  if [[ "${REQUIRE_PUBLIC_GATE:-0}" == "1" ]]; then
    echo "public-gate: PUBLIC_GATE_PATTERN not set and REQUIRE_PUBLIC_GATE=1" >&2
    exit 1
  fi
  echo "public-gate: SKIPPED (PUBLIC_GATE_PATTERN not set)"
  exit 0
fi

# Binary fixtures are generated from synthetic names; scan text only.
hits=$(git ls-files -z | xargs -0 grep -IinE -- "$PUBLIC_GATE_PATTERN" -- 2>/dev/null || true)
if [[ -n "$hits" ]]; then
  # Print file:line only, never the matched text (it is what must not leak).
  echo "public-gate: FAIL, forbidden content at:" >&2
  echo "$hits" | cut -d: -f1,2 >&2
  exit 1
fi
echo "public-gate: PASS ($(git ls-files | wc -l | tr -d ' ') files)"
