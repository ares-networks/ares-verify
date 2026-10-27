# ares-verify: DESIGN

Offline checker for replay packs. It has no network access, no config and no
state. Its input is one zip, and its output is a report plus an exit code. The
format is defined in `spec/FORMAT.md`. Code and spec change together.

```
cmd/ares-verify/     cobra CLI: <pack> [--json|--record N] [--pin] [--min-parties]; explain. exit 0/1/2
cmd/gen-fixtures/    writes testdata/*.zip from internal/fixtures
internal/pack/       zip reader (entry/size caps, no traversal, regular files only) + typed parse;
                     parse errors are kept per file so checks report them instead of aborting
internal/canon/      RFC 8785 JCS subset (integers only; fractions/exponents rejected)
internal/chain/      record hash = sha256(JCS(record - hash) || prevHash); seq/time/link checks
internal/fabtx/      ProposalResponsePayload -> ChaincodeAction -> rwset writes (own namespace);
                     endorsement = ECDSA DER over sha256(prp || SerializedIdentity)
internal/parties/    per-MSP root/intermediate pools, fingerprints computed (never trusted), pins
internal/checks/     the 6 checks in FORMAT.md §8 order -> Result{checks, summary, refusals, ok}
internal/report/     text (one line per check, first 5 problems) and JSON
internal/fixtures/   synthetic 2-org packs with real protos and signatures; BuildVariant(name)
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
- Dependencies stay small: cobra, fabric-protos-go-apiv2, protobuf. No ledger
  SDK.
- Public repository: no hostnames, deployment or customer names, or internal
  codes in code, fixtures or docs.

Fixture packs get new keys on every `make fixtures`. Tests build their own
packs in memory, so committed testdata is only used by CI's CLI smoke step.

## CI and releases

`make ci` is the whole gate: gofmt, vet, tests, CLI smoke on the committed
fixtures, reproducible build, public-content gate. Two CI front ends run it:
`bitbucket-pipelines.yml` (every push, PRs, and `v*` tags, which also build
`make dist` binaries + SHA256SUMS as artifacts; nothing is published) and
`.github/workflows/ci.yml` (for when the repo is mirrored to GitHub).

`scripts/public-gate.sh` greps tracked files for `PUBLIC_GATE_PATTERN`, a
secured CI variable. The pattern is never committed, because the names it
blocks are the ones that must not appear here. It reports file:line only.
Unset means skipped, except on `v*` tags, where it must be set.
