# ares-verify

Check a replay pack yourself, offline, without an account and without trusting
whoever gave it to you.

A replay pack is one zip file holding the record of what governed agents did
for a job: sessions opened and narrowed, what was refused and why, and what was
redacted. Each record points at the ledger write behind it, and that write
carries the signatures of the organisations that confirmed it.

## Install

Download a release binary for macOS, Linux or Windows, or build it:

```
go install github.com/ares-networks/ares-verify/cmd/ares-verify@latest
```

From a checkout: `make build` (writes `bin/ares-verify`), or
`go build -o ares-verify ./cmd/ares-verify`.

## Use

```
ares-verify pack.zip                  full check, human report; exit 0 pass, 1 fail, 2 unreadable
ares-verify pack.zip --json           machine report (result, warnings, checks, parties)
ares-verify pack.zip --pin <fp,...>   only count organisations whose root fingerprint you pinned
ares-verify pack.zip --min-parties 2  require at least two organisations per transaction
ares-verify pack.zip --record 118     one record, its transaction and endorsements
ares-verify explain                   what each check proves and what it does not
```

```
ares-verify valid.zip
  manifest        PASS  19 files, exporter sig ok
  chain           PASS  7 records, contiguous, 2026-10-14T09:02Z .. 09:41Z
  transactions    PASS  7/7 write sets match
  endorsements    PASS  2 of 2 parties on every transaction (Org1MSP, Org2MSP)
  redactions      PASS  2 records, 0 hashes-only
  summary               0 allowed, 1 refused, 2 redacted, 0 sent to a human, 1 revoked
  refused #5      send-external   reason: outside badge
  root                  Org1MSP b122c577…db617a1
  root                  Org2MSP 536f9ef1…3cf97e7
result: PASS
```

The `root` lines are each organisation's root certificate fingerprint,
computed from the pack (printed in full; shortened here).

## Reading the report

Each check prints `PASS`, `WARN` or `FAIL`. `result: PASS` means no check
failed; a `WARN` does not fail the pack. It marks something that could not be
checked, so read it before relying on the result.

| Exit | Meaning |
|---|---|
| 0 | `result: PASS` (warnings allowed) |
| 1 | `result: FAIL`: at least one check failed |
| 2 | the pack could not be read (missing file, not a zip) |

`--json` carries the same verdict as `result` (`PASS`/`FAIL`), the number of
checks that warned as `warnings`, every problem per check, and the parties
with their computed root fingerprints.

**Hashes-only packs.** An operator can export a pack that leaves out stripped
content and content-bearing exception bodies. Those records keep their hashes,
and their transactions ship withheld, with no payload and no endorsements. The
pack still passes, with a warning on that transaction:

```
ares-verify hashes-only.zip
  manifest        PASS  17 files, exporter sig ok
  chain           PASS  7 records, contiguous, 2026-10-14T09:02Z .. 09:41Z
  transactions    WARN  6/7 write sets match, 1 withheld (hashes-only, not verifiable)
  endorsements    PASS  2 of 2 parties on every endorsed transaction (Org1MSP, Org2MSP); 1 withheld (no endorsements)
  redactions      PASS  2 records, 2 hashes-only
  ...
result: PASS
```

A withheld transaction proves that a write happened at that key; it does not
prove what the write contained.

**"N of M parties".** M is the number of organisations that are members of
the transaction's channel (from `parties.json`), and N is how many of them
endorsed it with a valid signature. A ledger whose endorsement policy needs
one organisation shows `1 of 2`, which passes by default (`--min-parties 1`). Set `--min-parties` to what the operator's policy
promises: `--min-parties 2` fails every transaction endorsed by only one
organisation.

**What a FAIL looks like.** Each failing check names what is wrong:

```
ares-verify tampered-record.zip
  manifest        PASS  19 files, exporter sig ok
  chain           FAIL  seq 5: hash does not match content (record edited)
  ...
result: FAIL
```

Editing any file in the pack and re-zipping it fails `manifest`, because the
file's size and SHA-256 no longer match the signed list.

## Pinning the organisations' roots

Without `--pin`, the organisations' root certificates come from the pack
itself. To rule out a pack that brings its own roots, take the fingerprints
from a source you trust (for example the operator's published trust page) and
pass them with `--pin`.

- A fingerprint is the hex SHA-256 of the root certificate's DER encoding.
  The report's `root` lines (and `parties[].rootFingerprints` in `--json`)
  show the fingerprints computed from the pack. Compare them with the
  operator's published values; pin the published ones, not the pack's.
- Pin the exporter's organisation too. If it is not pinned, `endorsements`
  fails with `exporter party <MSP> is not pinned`.
- `--record N` prints each endorser's own certificate fingerprint. That is not
  a root fingerprint, so do not pin it.

## What is in a pack

| File | Holds |
|---|---|
| `manifest.json` | every file with its size and SHA-256, signed by the exporter |
| `parties.json` | the channel's organisations: root and intermediate certificates, channels |
| `records.jsonl` | the hash-chained records, one per line |
| `bodies/` | the exact ledger value a record points at (optional per record) |
| `tx/` | per transaction: the endorsed response payload and its endorsements |
| `redactions/` | redaction records, with stripped content or only its hash |
| `README.txt` | a short note for whoever receives the pack |

A pack never contains a transaction's envelope or its chaincode arguments,
because those can carry the caller's credentials. That is why `tx/` holds only
the endorsed part.

## What a PASS proves

- The pack is the one the exporter signed. No file was added, removed or changed.
- No record was edited, removed, inserted or reordered after export.
- Each record is exactly what the ledger stored at its key.
- The listed organisations endorsed those writes with their own keys.
- Stripped content, where included, matches the hash recorded at the time.

## What a PASS does not prove

- That the agents' outputs were correct or appropriate.
- That no call happened outside the recording path.
- That a transaction was committed in a given block. Block number, time and
  validation code are labels from the exporter, not signed by the ordering
  service in this version.
- That the pack holds every record that exists. It proves the included records
  were not altered or invented.

## Format

[spec/FORMAT.md](spec/FORMAT.md) is the normative format, and
[spec/replay-pack-v1.schema.json](spec/replay-pack-v1.schema.json) gives the
JSON shapes. `testdata/` holds synthetic packs: one valid, one hashes-only, and
four that are each broken in one way.

## Develop

```
make test vet       unit and fixture tests
make fixtures       regenerate testdata/
make repro          build twice, compare hashes
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
