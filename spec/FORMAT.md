# Replay pack format, version 1

Normative. "MUST" means a verifier fails the pack when it is not met. An exporter
and a verifier written independently from this page must agree.

## 1. Container

A zip file. Entry names are relative, use `/`, contain no `..` segment, and no
leading `/`. Every entry is a regular file. Recommended name:
`ares-replay-<tenant>-<scope>-<yyyymmdd>.zip`.

```
manifest.json          required
records.jsonl          required
parties.json           required
tx/<txId>.json         one per distinct non-empty record.tx
bodies/<seq>.json      optional per record: the exact ledger value the record points at
redactions/<id>.json   one per redaction record
README.txt             required, plain text, informative only
```

## 2. Canonical JSON

Where this page says JCS it means RFC 8785 (JSON Canonicalization Scheme):
object members sorted by key (UTF-16 code units), no insignificant whitespace,
strings escaped minimally (`\"`, `\\`, `\b`, `\f`, `\n`, `\r`, `\t`, other
code points below U+0020 as `\u00xx` with lowercase hex, everything else as
literal UTF-8). Pack JSON that is hashed or signed contains only strings,
booleans, null, arrays, objects and integers in [-(2^53)+1, 2^53-1], so the
number rules of RFC 8785 reduce to plain base-10 integers.

Hashes are SHA-256, written as 64 lowercase hex characters, except where a
field is documented as carrying a ledger value verbatim.

## 3. manifest.json

```json
{
  "packVersion": 1,
  "tenant": "<tenant id>",
  "scope": "job" | "session-tree",
  "root": {"sessionId": "...", "initiatorId": "...", "ownerId": "..."},
  "exportedAt": "2026-10-24T09:41:00Z",
  "exporter": {"mspId": "<MSP id>", "certPem": "-----BEGIN CERTIFICATE-----..."},
  "hashesOnly": false,
  "sources": {"sessions": "ledger" | "index", "monitor": "ledger" | "index" | "not-configured"},
  "files": [{"path": "records.jsonl", "sha256": "<hex>", "size": 1234}, ...],
  "signature": {"alg": "ECDSA-P256-SHA256", "value": "<base64 std, ASN.1 DER>"}
}
```

- `files` lists every zip entry except `manifest.json`, exactly once, and no
  other path. Each `sha256`/`size` is of the entry's uncompressed bytes.
- `signature.value` is an ECDSA signature over SHA-256 of JCS(manifest with
  the `signature` member removed), made with the private key of
  `exporter.certPem`.
- `exporter.certPem` MUST chain to a root of the party in `parties.json`
  whose `mspId` equals `exporter.mspId`.
- `sources.*` = `index` means the ledger had no block history (a store without
  one); records then carry no `tx` and check 3 reports it.

## 4. records.jsonl

One JSON object per line, UTF-8, `\n` line ends, no blank lines. The line
itself is the record; it need not be in JCS form, the verifier canonicalises.

| Field | Type | Meaning |
|---|---|---|
| `seq` | int | 1, 2, 3, ... contiguous in file order |
| `time` | string | RFC 3339 UTC; non-decreasing in file order |
| `kind` | string | see below |
| `session` | string | credential session id the record belongs to |
| `agent` | string | acting party id (may be empty) |
| `action` | string | capability / filter / violation the record is about (may be empty) |
| `decision` | string | `record` \| `allow` \| `narrow` \| `refuse` \| `redact` \| `revoke` \| `human` |
| `reason` | string | one line, may be empty |
| `channel` | string | ledger channel the write is on |
| `key` | string | ledger key written (composite keys keep their U+0000 separators) |
| `valueHash` | string | hex SHA-256 of the written value; `""` when the write is a delete |
| `tx` | string | transaction id that wrote `key`; `""` when unanchored |
| `prevHash` | string | `hash` of the previous record; 64 x `0` for seq 1 |
| `hash` | string | hex SHA-256( JCS(record without `hash`) bytes ‖ ASCII bytes of `prevHash` ) |

Kinds: `session-open`, `filters`, `activate`, `intersect`, `promote`,
`expire`, `session-write` (any other session write), `redaction`,
`guard-exception`, `language-exception`.

Unknown members are allowed and are covered by the hash.

## 5. tx/<txId>.json

```json
{
  "txId": "...",
  "channel": "...",
  "blockNumber": 42,
  "timestamp": "2026-10-14T09:02:11Z",
  "validationCode": "VALID",
  "function": "AresCredSessionCreate",
  "creatorMsp": "...",
  "proposalResponsePayload": "<base64 std>",
  "endorsements": [{"endorser": "<base64 std>", "signature": "<base64 std>"}],
  "withheld": false
}
```

- `proposalResponsePayload` is the exact `protos.ProposalResponsePayload`
  bytes from the endorsed transaction action. Its `extension` is a
  `protos.ChaincodeAction` whose `results` is a `rwset.TxReadWriteSet`.
- `endorser` is the exact `msp.SerializedIdentity` bytes; `signature` is the
  endorser's ECDSA DER signature over SHA-256(`proposalResponsePayload` ‖
  `endorser`).
- `function`, `blockNumber`, `timestamp`, `validationCode`, `creatorMsp` are
  labels copied by the exporter. They are not covered by any ledger signature
  in v1.
- `withheld: true` (hashes-only export of a write that holds content): the
  exporter omits `proposalResponsePayload` and `endorsements`. The verifier
  reports the record as anchored but not verifiable, never as a pass.
- The transaction envelope (and so the chaincode arguments) is never included.

## 6. parties.json

```json
[{
  "mspId": "...",
  "displayName": "...",
  "channels": ["..."],
  "rootCertsPem": ["-----BEGIN CERTIFICATE-----..."],
  "intermediateCertsPem": [],
  "fingerprints": ["<hex sha256 of each root cert DER, same order>"]
}]
```

From the channel configuration (application organisations). `channels` lists
every pack channel the organisation is a member of; M for a transaction is
the number of parties listing its channel.

## 7. bodies/<seq>.json and redactions/<id>.json

`bodies/<seq>.json` holds the exact value written to `key` (the file bytes are
the ledger bytes, whatever their format). If present, SHA-256(file) MUST equal
`valueHash`.

```json
{
  "seq": 17,
  "redactionId": "...",
  "filters": ["..."],
  "redactedDataHash": "<base64 std SHA-256, as stored on the ledger>",
  "offchainStorageOnly": false,
  "content": "<base64 std of the stripped bytes>" | null
}
```

If `content` is non-null, base64(SHA-256(decoded content)) MUST equal
`redactedDataHash`. `content: null` is reported as hash-only. `seq` MUST name a
record of kind `redaction`.

## 8. Checks (in order)

1. **manifest**: every listed file present with matching size and SHA-256, no
   unlisted entry, signature valid, exporter cert chains to its party.
2. **chain**: seq contiguous from 1, time non-decreasing, every `prevHash` and
   `hash` recomputes.
3. **transactions**: for every record with `tx`: `tx/<tx>.json` exists, its
   channel equals the record's, the ProposalResponsePayload decodes, and the
   chaincode's own namespace in the rwset has a write to `key` whose value
   hashes to `valueHash` (or is a delete when `valueHash` is ""). Records with
   empty `tx` and withheld transactions are counted and reported (WARN), not
   passed silently.
4. **endorsements**: each endorsement signature verifies with the endorser's
   certificate; the certificate chains to a root of the party named by its MSP
   id, at the transaction timestamp; N = distinct parties with a valid
   endorsement, M = parties on the channel. FAIL when N < the required minimum
   (default 1) or any present endorsement is invalid. With `--pin`, only
   parties having a pinned root fingerprint count, and the exporter's party
   must be pinned.
5. **redactions**: content hashes match; hash-only records listed.
6. **summary**: counts by decision; every `refuse` record with its reason.

## 9. What a PASS does not prove

That the agents' outputs were correct; that no call happened outside the
recording path; that the transaction was committed in a given block (block
inclusion and validation code are not signed by the ordering service in v1);
that the exporter included every record that exists (it proves the included
ones were not altered or invented).
