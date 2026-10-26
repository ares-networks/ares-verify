// Package fixtures builds synthetic replay packs: two test organisations with
// their own CAs, real ledger protobuf structures and real signatures. It is
// what the tests and cmd/gen-fixtures use, and the reference for how an
// exporter lays a pack out.
package fixtures

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"

	"github.com/ares-networks/ares-verify/internal/canon"
	"github.com/ares-networks/ares-verify/internal/chain"
	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/internal/parties"
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
}

func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// NewOrg creates an organisation with a fresh P-256 CA and leaf.
func NewOrg(mspID string) (*Org, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca." + mspID, Organization: []string{mspID}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "peer0." + mspID, Organization: []string{mspID}},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(leafDER)
	return &Org{MSPID: mspID, CACert: caCert, CAKey: caKey, CAPEM: pemCert(caDER),
		Cert: leaf, Key: key, CertPEM: pemCert(leafDER)}, nil
}

// Identity is the msp.SerializedIdentity of the org's leaf.
func (o *Org) Identity() []byte {
	b, _ := proto.Marshal(&msp.SerializedIdentity{Mspid: o.MSPID, IdBytes: []byte(o.CertPEM)})
	return b
}

// Endorse signs SHA-256(prp || identity), DER, low-S (as the ledger does).
func (o *Org) Endorse(prp []byte) (endorser, sig []byte, err error) {
	endorser = o.Identity()
	d := sha256.Sum256(append(append([]byte{}, prp...), endorser...))
	sig, err = SignLowS(o.Key, d[:])
	return endorser, sig, err
}

// SignLowS returns an ASN.1 DER ECDSA signature with S in the lower half.
func SignLowS(k *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, err
	}
	n := k.Curve.Params().N
	if rs.S.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		rs.S.Sub(n, rs.S)
	}
	return asn1.Marshal(rs)
}

// KVWrite is one write in a fixture transaction.
type KVWrite struct {
	Key      string
	Value    []byte
	IsDelete bool
}

// BuildPRP builds ProposalResponsePayload{proposal_hash, extension:
// ChaincodeAction{results: TxReadWriteSet{KV, [NsReadWriteSet{namespace:
// chaincode, rwset: KVRWSet{writes}}]}, chaincode_id{name, version},
// response{200}}}.
func BuildPRP(chaincode, txID string, writes []KVWrite) ([]byte, error) {
	kv := &kvrwset.KVRWSet{}
	for _, w := range writes {
		kv.Writes = append(kv.Writes, &kvrwset.KVWrite{Key: w.Key, Value: w.Value, IsDelete: w.IsDelete})
	}
	kvb, err := proto.Marshal(kv)
	if err != nil {
		return nil, err
	}
	txrw, err := proto.Marshal(&rwset.TxReadWriteSet{
		DataModel: rwset.TxReadWriteSet_KV,
		NsRwset:   []*rwset.NsReadWriteSet{{Namespace: chaincode, Rwset: kvb}},
	})
	if err != nil {
		return nil, err
	}
	ca, err := proto.Marshal(&peer.ChaincodeAction{
		Results:     txrw,
		ChaincodeId: &peer.ChaincodeID{Name: chaincode, Version: "1.0"},
		Response:    &peer.Response{Status: 200},
	})
	if err != nil {
		return nil, err
	}
	ph := sha256.Sum256([]byte("proposal:" + txID))
	return proto.Marshal(&peer.ProposalResponsePayload{ProposalHash: ph[:], Extension: ca})
}

// CompositeKey mimics the ledger's composite key layout.
func CompositeKey(objectType string, attrs ...string) string {
	return "\x00" + objectType + "\x00" + strings.Join(attrs, "\x00") + "\x00"
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
	Files    map[string][]byte
	Exporter *Org
}

// Build lays out every file and signs the manifest.
func Build(s Spec) (*Pack, error) {
	p := &Pack{Files: map[string][]byte{}, Exporter: s.Exporter}
	channels := map[string]bool{}
	var lines []map[string]any
	for i := range s.Entries {
		e := &s.Entries[i]
		seq := i + 1
		channels[e.Channel] = true
		if e.TxID == "" {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", s.Tenant, seq)))
			e.TxID = hex.EncodeToString(h[:])
		}
		value := e.Value
		var redFile *pack.Redaction
		if e.Redaction != nil {
			v, rf, err := redactionValue(e, seq, s.HashesOnly)
			if err != nil {
				return nil, err
			}
			value, redFile = v, rf
		}
		valueHash := ""
		if !e.Delete {
			vh := sha256.Sum256(value)
			valueHash = hex.EncodeToString(vh[:])
		}
		contentOnLedger := e.Redaction != nil && !e.Redaction.OffchainOnly
		withheld := s.HashesOnly && contentOnLedger

		tx := pack.Tx{TxID: e.TxID, Channel: e.Channel, BlockNumber: uint64(10 + seq),
			Timestamp: e.Time.UTC().Format(time.RFC3339), ValidationCode: "VALID",
			Function: "fixture" + strings.ReplaceAll(e.Kind, "-", ""), CreatorMSP: s.Exporter.MSPID,
			Endorsements: []pack.Endorsement{}, Withheld: withheld}
		if !withheld {
			prp, err := BuildPRP(e.Chain, e.TxID, []KVWrite{{Key: e.Key, Value: value, IsDelete: e.Delete}})
			if err != nil {
				return nil, err
			}
			tx.ProposalResponsePayload = base64.StdEncoding.EncodeToString(prp)
			endorsers := e.Endorsers
			if endorsers == nil {
				endorsers = s.Orgs
			}
			for _, o := range endorsers {
				eb, sig, err := o.Endorse(prp)
				if err != nil {
					return nil, err
				}
				tx.Endorsements = append(tx.Endorsements, pack.Endorsement{
					Endorser:  base64.StdEncoding.EncodeToString(eb),
					Signature: base64.StdEncoding.EncodeToString(sig)})
			}
		}
		txb, _ := json.MarshalIndent(tx, "", "  ")
		p.Files["tx/"+e.TxID+".json"] = txb

		if !e.NoBody && !e.Delete && !(s.HashesOnly && e.Redaction != nil) {
			p.Files[fmt.Sprintf("bodies/%d.json", seq)] = value
		}
		if redFile != nil {
			rb, _ := json.MarshalIndent(redFile, "", "  ")
			p.Files["redactions/"+e.Redaction.ID+".json"] = rb
		}
		lines = append(lines, map[string]any{
			"seq": json.Number(fmt.Sprint(seq)), "time": e.Time.UTC().Format(time.RFC3339),
			"kind": e.Kind, "session": e.Session, "agent": e.Agent, "action": e.Action,
			"decision": e.Decision, "reason": e.Reason, "channel": e.Channel, "key": e.Key,
			"valueHash": valueHash, "tx": e.TxID,
		})
	}
	if err := p.WriteRecords(lines, true); err != nil {
		return nil, err
	}

	chs := make([]string, 0, len(channels))
	for c := range channels {
		chs = append(chs, c)
	}
	sort.Strings(chs)
	var ps []pack.Party
	for _, o := range s.Orgs {
		ps = append(ps, pack.Party{MSPID: o.MSPID, DisplayName: o.MSPID, Channels: chs,
			RootCertsPEM: []string{o.CAPEM}, IntermediateCertsPEM: []string{},
			Fingerprints: []string{parties.Fingerprint(o.CACert)}})
	}
	pb, _ := json.MarshalIndent(ps, "", "  ")
	p.Files["parties.json"] = pb
	p.Files["README.txt"] = []byte(readme)

	m := pack.Manifest{PackVersion: 1, Tenant: s.Tenant, Scope: s.Scope, Root: s.Root,
		ExportedAt: s.ExportedAt.UTC().Format(time.RFC3339),
		Exporter:   pack.Exporter{MSPID: s.Exporter.MSPID, CertPEM: s.Exporter.CertPEM},
		HashesOnly: s.HashesOnly, Sources: pack.Sources{Sessions: "ledger", Monitor: "ledger"}}
	mb, _ := json.Marshal(m)
	p.Files["manifest.json"] = mb
	return p, p.Resign()
}

func redactionValue(e *Entry, seq int, hashesOnly bool) ([]byte, *pack.Redaction, error) {
	r := e.Redaction
	sum := sha256.Sum256(r.Content)
	hash := base64.StdEncoding.EncodeToString(sum[:])
	ledger := map[string]any{
		"id": r.ID, "senderId": e.Agent, "receiverId": "receiver", "credSessionId": e.Session,
		"utc": e.Time.Unix(), "redactionFilters": r.Filters, "redactedDataHash": hash,
	}
	if !r.OffchainOnly {
		ledger["redactedDataJson"] = json.RawMessage(r.Content)
	}
	v, err := json.Marshal(ledger)
	if err != nil {
		return nil, nil, err
	}
	rf := &pack.Redaction{Seq: seq, RedactionID: r.ID, Filters: r.Filters, RedactedDataHash: hash,
		OffchainStorageOnly: r.OffchainOnly}
	if !hashesOnly {
		c := base64.StdEncoding.EncodeToString(r.Content)
		rf.Content = &c
	}
	return v, rf, nil
}

// WriteRecords writes records.jsonl. With rechain, prevHash/hash are
// recomputed (what an exporter does); without, lines are written as given.
func (p *Pack) WriteRecords(lines []map[string]any, rechain bool) error {
	var buf bytes.Buffer
	prev := chain.Genesis
	for _, l := range lines {
		if rechain {
			l["prevHash"] = prev
			delete(l, "hash")
			h, err := chain.Hash(l)
			if err != nil {
				return err
			}
			l["hash"] = h
			prev = h
		}
		b, err := json.Marshal(l)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	p.Files["records.jsonl"] = buf.Bytes()
	return nil
}

// Records returns records.jsonl as decoded maps.
func (p *Pack) Records() ([]map[string]any, error) {
	recs, err := pack.ParseRecords(p.Files["records.jsonl"])
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, len(recs))
	for i, r := range recs {
		out[i] = r.Raw
	}
	return out, nil
}

// Resign recomputes manifest.files and the exporter signature, as an
// exporter holding the key would.
func (p *Pack) Resign() error {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(p.Files["manifest.json"]))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return err
	}
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		if n != "manifest.json" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	files := make([]any, 0, len(names))
	for _, n := range names {
		s := sha256.Sum256(p.Files[n])
		files = append(files, map[string]any{"path": n, "sha256": hex.EncodeToString(s[:]),
			"size": json.Number(fmt.Sprint(len(p.Files[n])))})
	}
	m["files"] = files
	delete(m, "signature")
	b, err := canon.Encode(m)
	if err != nil {
		return err
	}
	d := sha256.Sum256(b)
	sig, err := SignLowS(p.Exporter.Key, d[:])
	if err != nil {
		return err
	}
	m["signature"] = map[string]any{"alg": "ECDSA-P256-SHA256", "value": base64.StdEncoding.EncodeToString(sig)}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	p.Files["manifest.json"] = append(out, '\n')
	return nil
}

// Zip writes the pack with stable entry order and timestamps.
func (p *Pack) Zip() ([]byte, error) {
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		if n != "manifest.json" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	if _, ok := p.Files["manifest.json"]; ok {
		names = append([]string{"manifest.json"}, names...)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate,
			Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(p.Files[n]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
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

const readme = `This is a replay pack: a signed export of what was recorded for one job.

Check it with ares-verify (open source):

    ares-verify <this file>.zip

A PASS means the records were not edited, removed or reordered after export,
each record matches the ledger write it points at, and the listed
organisations endorsed those writes with their own keys.

A PASS does not mean the agents' outputs were correct, that nothing happened
outside the recording path, or that the pack holds every record that exists.
`
