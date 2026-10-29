# pkg/replaypack: DESIGN

Public Go package that builds FORMAT.md v1 packs. Import path
`github.com/ares-networks/ares-verify/pkg/replaypack`.

```
doc.go        package comment
types.go      wire types (manifest, tx, party, redaction); internal/pack aliases them
canon.go      GenesisHash, RecordHash (JCS via internal/canon), Fingerprint
identity.go   CA (NewCA, Issue), Identity (NewIdentity from PEM, NewEphemeralIdentity),
              Endorse, Sign, SignLowS
fabric.go     KVWrite, BuildPRP, CompositeKey
build.go      Spec/PartySpec/Entry/RedactionSpec, Build, Pack (WriteRecords, Records,
              Resign, Zip), DefaultReadme
*_test.go     round trips through internal/pack + internal/checks; ExampleBuild
```

Rules:
- Build lays out; it does not judge. It signs entries the verifier will fail
  (time outside a certificate's validity), so tests can build bad packs. It
  rejects only specs it cannot lay out: no exporter, exporter not a party,
  time going backwards, missing channel/chaincode/key, reused tx or redaction id.
- Defaults: TxID = hex sha256("<tenant>/<seq>"), BlockNumber = seq,
  CreatorMSP = exporter, DisplayName = MSP id, Channels = every pack channel,
  Sources = ledger/ledger, README.txt = DefaultReadme.
- Redaction entry: Value nil = Build writes a redaction record value; Value set
  = those are the stored ledger bytes. redactedDataHash = base64 std
  sha256(Content) either way.
- NewIdentity: P-256 key matching the cert, cert chains directly to a given CA
  root at its NotBefore. No intermediates.
- Zip: manifest.json first, then name order, mtime 2026-01-01: equal files,
  equal zip.
- Generic names only in code and tests (DemoMSP, example-tenant, agent-a).
