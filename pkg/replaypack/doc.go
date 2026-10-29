// Package replaypack builds replay packs in the layout of spec/FORMAT.md,
// version 1: hash-chained records, the endorsed write behind each record,
// the parties' roots, and a manifest signed by the exporter.
//
// It lays the format out and never interprets it. Whether a pack is sound is
// decided by the verifier (cmd/ares-verify), not by this package: Build signs
// whatever it is given, including entries a verifier will fail (for example a
// transaction time outside an endorser's certificate validity).
//
// Identities come from PEM files (NewIdentity) or are generated in memory
// (NewEphemeralIdentity, NewCA). Keys are ECDSA P-256.
//
// A change to the format changes FORMAT.md, the verifier and this package
// together.
package replaypack
