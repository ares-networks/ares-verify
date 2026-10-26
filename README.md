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

## Use

```
ares-verify pack.zip                  full check, human report; exit 0 pass, 1 fail, 2 unreadable
ares-verify pack.zip --json           machine report
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
result: PASS
```

Without `--pin`, the organisations' root certificates come from the pack
itself. To rule out a pack that brings its own roots, take the fingerprints
from a source you trust (for example the operator's published trust page) and
pass them with `--pin`.

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
