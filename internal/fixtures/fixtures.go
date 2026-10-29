// Package fixtures builds the synthetic test packs: two test organisations
// with their own CAs, real ledger protobuf structures and real signatures. It
// is a thin layer over pkg/replaypack that fixes the fixture conventions
// (function labels, block numbers, party names, README) so the committed
// testdata keeps its layout.
package fixtures

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"strings"
	"time"

	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/pkg/replaypack"
)

// Validity window for every fixture certificate, wide so committed fixtures
// keep verifying.
var (
	notBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter  = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Org is a test organisation: a root CA and one signing identity under it.
type Org struct {
	MSPID   string
	CACert  *x509.Certificate
	CAKey   *ecdsa.PrivateKey
	CAPEM   string
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM string

	id *replaypack.Identity
}

// NewOrg creates an organisation with a fresh P-256 CA and leaf.
func NewOrg(mspID string) (*Org, error) {
	ca, err := replaypack.NewCA("ca."+mspID, mspID, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	certPEM, keyPEM, err := ca.Issue("peer0."+mspID, mspID, notBefore, notAfter)
	if err != nil {
		return nil, err
	}
	id, err := replaypack.NewIdentity(mspID, certPEM, keyPEM, ca.CertPEM)
	if err != nil {
		return nil, err
	}
	return &Org{MSPID: mspID, CACert: ca.Cert, CAKey: ca.Key, CAPEM: ca.CertPEM,
		Cert: id.Cert, Key: id.Key, CertPEM: id.CertPEM, id: id}, nil
}

// Identity is the msp.SerializedIdentity of the org's leaf.
func (o *Org) Identity() []byte { return o.id.SerializedIdentity() }

// Endorse signs SHA-256(prp || identity), DER, low-S (as the ledger does).
func (o *Org) Endorse(prp []byte) (endorser, sig []byte, err error) { return o.id.Endorse(prp) }

// SignLowS returns an ASN.1 DER ECDSA signature with S in the lower half.
func SignLowS(k *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	return replaypack.SignLowS(k, digest)
}

// KVWrite is one write in a fixture transaction.
type KVWrite = replaypack.KVWrite

// BuildPRP builds a ProposalResponsePayload; see replaypack.BuildPRP.
func BuildPRP(chaincode, txID string, writes []KVWrite) ([]byte, error) {
	return replaypack.BuildPRP(chaincode, txID, writes)
}

// CompositeKey mimics the ledger's composite key layout.
func CompositeKey(objectType string, attrs ...string) string {
	return replaypack.CompositeKey(objectType, attrs...)
}

// RedactionEntry describes the redaction record behind a redaction entry.
type RedactionEntry struct {
	ID           string
	Filters      []string
	Content      []byte // the stripped bytes (JSON)
	OffchainOnly bool   // ledger value keeps the hash only
}

// Entry is one record and the transaction that wrote it.
type Entry struct {
	Time     time.Time
	Kind     string
	Session  string
	Agent    string
	Action   string
	Decision string
	Reason   string
	Channel  string
	Chain    string // chaincode name
	Key      string
	Value    []byte
	Delete   bool
	TxID     string
	// Endorsers: nil means every org; an empty non-nil slice means none.
	Endorsers []*Org
	Redaction *RedactionEntry
	NoBody    bool
}

// Spec describes a pack to build.
type Spec struct {
	Tenant     string
	Scope      string
	Root       pack.Root
	Orgs       []*Org
	Exporter   *Org
	HashesOnly bool
	ExportedAt time.Time
	Entries    []Entry
}

// Pack is a built pack as a set of files.
type Pack struct {
	*replaypack.Pack
}

// Build lays out every file and signs the manifest, with the fixture
// conventions: function "fixture<kind>", block 10+seq, display name = MSP id.
func Build(s Spec) (*Pack, error) {
	rs := replaypack.Spec{Tenant: s.Tenant, Scope: s.Scope, Root: s.Root, HashesOnly: s.HashesOnly,
		ExportedAt: s.ExportedAt, Readme: readme,
		Sources: replaypack.Sources{Sessions: "ledger", Monitor: "ledger"}}
	if s.Exporter != nil {
		rs.Exporter = s.Exporter.id
	}
	for _, o := range s.Orgs {
		rs.Parties = append(rs.Parties, replaypack.PartySpec{Identity: o.id, DisplayName: o.MSPID})
	}
	for i, e := range s.Entries {
		re := replaypack.Entry{Time: e.Time, Kind: e.Kind, Session: e.Session, Agent: e.Agent,
			Action: e.Action, Decision: e.Decision, Reason: e.Reason, Channel: e.Channel,
			Chaincode: e.Chain, Key: e.Key, Value: e.Value, Delete: e.Delete, TxID: e.TxID,
			BlockNumber: uint64(10 + i + 1), Function: "fixture" + strings.ReplaceAll(e.Kind, "-", ""),
			NoBody: e.NoBody}
		if e.Endorsers != nil {
			re.Endorsers = []*replaypack.Identity{}
			for _, o := range e.Endorsers {
				re.Endorsers = append(re.Endorsers, o.id)
			}
		}
		if r := e.Redaction; r != nil {
			re.Redaction = &replaypack.RedactionSpec{ID: r.ID, Filters: r.Filters, Content: r.Content,
				OffchainOnly: r.OffchainOnly, SenderID: e.Agent, ReceiverID: "receiver"}
		}
		rs.Entries = append(rs.Entries, re)
	}
	p, err := replaypack.Build(rs)
	if err != nil {
		return nil, err
	}
	return &Pack{p}, nil
}

// Load parses the built pack the way the verifier will.
func (p *Pack) Load(name string) (*pack.Pack, error) {
	z, err := p.Zip()
	if err != nil {
		return nil, err
	}
	lp, err := pack.Read(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		return nil, err
	}
	lp.Name = name
	return lp, nil
}

const readme = replaypack.DefaultReadme
