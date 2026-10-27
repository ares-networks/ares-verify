#!/usr/bin/env bash
# Pushes one ref (main, or a v* tag) to the public GitHub mirror.
#
#   scripts/mirror-github.sh main          push the built commit to main
#   scripts/mirror-github.sh tag v0.1.0    push an annotated tag
#   scripts/mirror-github.sh check <rev>   run the history guard only (no push)
#
# Runs in CI after the checks. It refuses rather than pushes when anything in
# the history should not be public, and it never force-pushes: the mirror only
# fast-forwards, so a rewrite here cannot silently rewrite the public copy.
#
# Guard, over every commit reachable from what is pushed (plus the tag itself):
#   - no co-author trailer naming an AI assistant
#   - author, committer and tagger emails match MIRROR_EMAIL_ALLOW
#   - no commit or tag text matches PUBLIC_GATE_PATTERN (reports ids only)
#   - tracked files pass scripts/public-gate.sh with the gate required
#
# Env:
#   GITHUB_MIRROR_KEY    base64 of the deploy key's private key (secured)
#   GITHUB_MIRROR_REPO   default git@github.com:ares-networks/ares-verify.git
#   PUBLIC_GATE_PATTERN  as for scripts/public-gate.sh; required, except `check`
#   MIRROR_EMAIL_ALLOW   extended regex, default @ares-networks\.com$
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="${GITHUB_MIRROR_REPO:-git@github.com:ares-networks/ares-verify.git}"
allow="${MIRROR_EMAIL_ALLOW:-@ares-networks\\.com$}"
mode="${1:-}"
keydir=""   # global: the EXIT trap runs after push() has returned

die() { echo "mirror: $*" >&2; exit 1; }

guard() { # <rev> [tag]
  local rev="$1" tag="${2:-}" bad=0 c e
  for c in $(git rev-list "$rev"); do
    if git log -1 --format=%B "$c" | grep -qiE '^co-authored-by:.*(claude|anthropic|copilot|openai|gpt)'; then
      echo "mirror: $c has an AI co-author trailer" >&2; bad=1
    fi
    for e in $(git log -1 --format='%ae %ce' "$c"); do
      echo "$e" | grep -qE -- "$allow" || { echo "mirror: $c email not allowed (author/committer)" >&2; bad=1; }
    done
    if [[ -n "${PUBLIC_GATE_PATTERN:-}" ]] &&
      git log -1 --format='%an%n%ae%n%cn%n%ce%n%B' "$c" | grep -qiE -- "$PUBLIC_GATE_PATTERN"; then
      echo "mirror: $c message or identity matches the public gate" >&2; bad=1
    fi
  done
  if [[ -n "$tag" ]]; then
    e="$(git for-each-ref "refs/tags/$tag" --format='%(taggeremail:trim)')"
    echo "$e" | grep -qE -- "$allow" || { echo "mirror: tag $tag tagger email not allowed" >&2; bad=1; }
    if git for-each-ref "refs/tags/$tag" --format='%(contents)' | grep -qiE '^co-authored-by:.*(claude|anthropic|copilot|openai|gpt)'; then
      echo "mirror: tag $tag has an AI co-author trailer" >&2; bad=1
    fi
    if [[ -n "${PUBLIC_GATE_PATTERN:-}" ]] &&
      git for-each-ref "refs/tags/$tag" --format='%(taggername)%0a%(taggeremail)%0a%(contents)' | grep -qiE -- "$PUBLIC_GATE_PATTERN"; then
      echo "mirror: tag $tag matches the public gate" >&2; bad=1
    fi
  fi
  [[ $bad -eq 0 ]] || die "refusing: history is not ready to be public"
  echo "mirror: guard ok ($(git rev-list --count "$rev") commits${tag:+, tag $tag})"
}

push() { # <src> <dst ref>
  local src="$1" dst="$2" want got
  [[ -n "${GITHUB_MIRROR_KEY:-}" ]] || die "GITHUB_MIRROR_KEY is not set"
  [[ -n "${PUBLIC_GATE_PATTERN:-}" ]] || die "PUBLIC_GATE_PATTERN is not set (required to mirror)"
  REQUIRE_PUBLIC_GATE=1 "$here/public-gate.sh"
  [[ "$(git rev-parse --is-shallow-repository)" == false ]] || die "shallow clone; GitHub needs full history (clone depth: full)"
  keydir="$(mktemp -d)"
  trap '[[ -n "$keydir" ]] && rm -rf "$keydir"' EXIT
  printf '%s' "$GITHUB_MIRROR_KEY" | base64 -d > "$keydir/key" 2>/dev/null || die "GITHUB_MIRROR_KEY is not base64"
  chmod 600 "$keydir/key"
  export GIT_SSH_COMMAND="ssh -i $keydir/key -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$here/github_known_hosts"
  git push "$repo" "$src:$dst"
  want="$(git rev-parse "$src")"
  got="$(git ls-remote "$repo" "$dst" | cut -f1)"
  [[ "$got" == "$want" ]] || die "after push GitHub $dst is ${got:-missing}, expected $want"
  echo "mirror: GitHub $dst = $want"
}

case "$mode" in
  main)
    rev="${BITBUCKET_COMMIT:-HEAD}"
    guard "$rev"
    push "$rev" refs/heads/main
    ;;
  tag)
    tag="${2:?usage: mirror-github.sh tag <name>}"
    if [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" != tag ]]; then
      git fetch --no-tags origin "+refs/tags/$tag:refs/tags/$tag" >/dev/null 2>&1 || true
    fi
    [[ "$(git cat-file -t "refs/tags/$tag" 2>/dev/null)" == tag ]] || die "tag $tag is missing or not annotated"
    guard "refs/tags/$tag^{commit}" "$tag"
    push "refs/tags/$tag" "refs/tags/$tag"
    ;;
  check)
    rev="${2:-HEAD}"
    [[ -n "${PUBLIC_GATE_PATTERN:-}" ]] || echo "mirror: PUBLIC_GATE_PATTERN not set; gate part of the guard skipped" >&2
    if [[ "$(git cat-file -t "$rev" 2>/dev/null)" == tag ]]; then
      guard "$rev^{commit}" "${rev#refs/tags/}"
    else
      guard "$rev"
    fi
    ;;
  *)
    echo "usage: $0 main | tag <name> | check [<rev>]" >&2
    exit 2
    ;;
esac
