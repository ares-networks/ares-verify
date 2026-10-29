# ares-verify: DESIGN

Offline checker for replay packs. It has no network access, no config and no
state. Its input is one zip, and its output is a report plus an exit code. The
format is defined in `spec/FORMAT.md`. Code and spec change together.

```
cmd/ares-verify/     cobra CLI: <pack> [--json|--record N] [--pin] [--min-parties]; explain. exit 0/1/2
cmd/gen-fixtures/    writes testdata/*.zip from internal/fixtures
pkg/replaypack/      PUBLIC builder: wire types, record hash, fingerprints, identities (PEM or
                     ephemeral), PRP + composite keys, Build/Resign/Zip. Lays out FORMAT.md v1
internal/pack/       zip reader (entry/size caps, no traversal, regular files only) + typed parse;
                     parse errors are kept per file so checks report them instead of aborting;
                     wire types are aliases of pkg/replaypack's
internal/canon/      RFC 8785 JCS subset (integers only; fractions/exponents rejected)
internal/chain/      record hash = sha256(JCS(record - hash) || prevHash) (replaypack.RecordHash);
                     seq/time/link checks
internal/fabtx/      ProposalResponsePayload -> ChaincodeAction -> rwset writes (own namespace);
                     endorsement = ECDSA DER over sha256(prp || SerializedIdentity)
internal/parties/    per-MSP root/intermediate pools, fingerprints computed (never trusted), pins
internal/checks/     the 6 checks in FORMAT.md §8 order -> Result{checks, summary, refusals, ok}
internal/report/     text (one line per check, first 5 problems, root fingerprints) and JSON
                     (result, warnings, checks, summary, refusals, parties)
internal/fixtures/   synthetic 2-org packs over pkg/replaypack; fixes function "fixture<kind>",
                     block 10+seq, displayName = MSP id; BuildVariant(name)
spec/                FORMAT.md (normative), replay-pack-v1.schema.json (shapes)
testdata/            valid, hashes-only (PASS), tampered-record, dropped-record,
                     missing-endorsement, swapped-party-cert (FAIL)
```

Rules that are easy to break:
- Check statuses are PASS / FAIL / WARN (summary uses INFO). Anything that
  could not be checked is WARN, never PASS: unanchored records and withheld
  transactions.
- Only the endorsed part of a transaction is in a pack. The envelope, and so
  the chaincode arguments, never is. Do not add envelope-signature checks
  without a format version bump.
- Endorser certificates are checked at the transaction's labelled time, and the
  exporter certificate at `exportedAt`, so a later certificate expiry does not
  turn old evidence into FAIL.
- With `--pin`, an unpinned organisation's valid endorsement does not count,
  and the exporter's organisation must be pinned.
- Root fingerprints in the report (text `root` lines, JSON
  `parties[].rootFingerprints`) are computed from the root certificates, never
  copied from `parties.json` `fingerprints`. They are for comparing with a
  trusted source before pinning.
- Withheld transactions have no endorsements, so the endorsements check skips
  them and its detail says how many ("on every endorsed transaction; N
  withheld"), never "every transaction".
- Dependencies stay small: cobra, fabric-protos-go-apiv2, protobuf. No ledger
  SDK. `pkg/replaypack` imports only the standard library, fabric-protos,
  protobuf and `internal/canon`; the verifier packages import it, never the
  other way round.
- `pkg/replaypack` lays out FORMAT.md and never interprets it; a format change
  bumps both (and the verifier) together. Its API is public: breaking it is a
  major version, adding to it a minor one.
- Public repository: no hostnames, deployment or customer names, or internal
  codes in code, fixtures, docs or commit messages. Commits carry an
  `@ares-networks.com` identity and no AI co-author trailers.

Fixture packs get new keys on every `make fixtures`. Tests build their own
packs in memory, so committed testdata is only used by CI's CLI smoke step.

## CI, mirror and releases

`make ci` is the whole gate: gofmt, vet, tests, CLI smoke on the committed
fixtures, reproducible build, public-content gate. It runs on every push and PR
in the upstream repository (`bitbucket-pipelines.yml`).

The public GitHub repository is a mirror. Upstream `main` and `v*` tags are
pushed to it by `scripts/mirror-github.sh` after the checks pass. The script:

- never force-pushes; the mirror only fast-forwards, so a history rewrite
  upstream fails the mirror step instead of rewriting the public copy;
- refuses to push if any commit or tag in the pushed history has an AI
  co-author trailer, an author/committer/tagger email outside
  `MIRROR_EMAIL_ALLOW` (default `@ares-networks.com`), or text matching
  `PUBLIC_GATE_PATTERN`, and re-runs the file gate with the pattern required;
- uses a write deploy key (`GITHUB_MIRROR_KEY`, base64, secured) and pins
  GitHub's host keys from `scripts/github_known_hosts`.

`make mirror-check` runs the history guard locally. Upstream merges must keep
the author identity on `@ares-networks.com`: a merge commit made under another
email stops the mirror until fixed.

On GitHub: `ci.yml` (main) re-runs the checks, `release.yml` (v* tags) builds
`make dist` binaries + SHA256SUMS and publishes a release with the tag's
annotation as notes, and `close-pull-requests.yml` closes pull requests with a
pointer to issues. The public-content gate pattern exists only upstream.

`scripts/public-gate.sh` greps tracked files for `PUBLIC_GATE_PATTERN`, a
secured CI variable. The pattern is never committed, because the names it
blocks are the ones that must not appear here. It reports file:line only.
Unset means skipped, except on `v*` tags and when mirroring, where it must be
set.
