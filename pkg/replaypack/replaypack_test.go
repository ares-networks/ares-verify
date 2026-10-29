package replaypack_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/ares-networks/ares-verify/internal/checks"
	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/pkg/replaypack"
)

var (
	t0 = time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	nb = t0.Add(-time.Hour)
	na = t0.Add(24 * time.Hour)
)

func at(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }

func demoIdentity(t *testing.T) (*replaypack.CA, *replaypack.Identity) {
	t.Helper()
	ca, err := replaypack.NewCA("Demo root", "Demo organisation", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, err := ca.Issue("demo exporter", "Demo organisation", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	id, err := replaypack.NewIdentity("DemoMSP", cert, key, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca, id
}

const redContent = `"card ending [redacted]"`

var redValue = []byte(`{"id":"red-1","redactedDataJson":"card ending [redacted]"}`)

func demoSpec(id *replaypack.Identity) replaypack.Spec {
	const sess = "sess-1"
	sk := replaypack.CompositeKey("session", "agent-a", sess)
	return replaypack.Spec{
		Tenant: "example-tenant", Scope: "job",
		Root:     replaypack.Root{SessionID: sess, InitiatorID: "agent-a", OwnerID: "agent-a"},
		Parties:  []replaypack.PartySpec{{Identity: id, DisplayName: "Demo organisation"}},
		Exporter: id, ExportedAt: at(30),
		Entries: []replaypack.Entry{
			{Time: at(0), Kind: "session-open", Session: sess, Agent: "agent-a", Action: "orders.read", Decision: "allow",
				Reason: "session opened", Channel: "sessions", Chaincode: "sessions-cc", Key: sk, Value: []byte(`{"state":"open"}`)},
			{Time: at(1), Kind: "session-write", Session: sess, Agent: "agent-a", Action: "orders.write", Decision: "refuse",
				Reason: "not in badge", Channel: "sessions", Chaincode: "sessions-cc",
				Key: replaypack.CompositeKey("decision", sess, "1"), Value: []byte(`{"decision":"refuse"}`), Function: "DecisionRecord"},
			{Time: at(2), Kind: "redaction", Session: sess, Agent: "agent-a", Action: "filter-card", Decision: "redact",
				Channel: "monitor", Chaincode: "monitor-cc", Key: replaypack.CompositeKey("redaction", "agent-a", "agent-b", "red-1"),
				Value:     redValue,
				Redaction: &replaypack.RedactionSpec{ID: "red-1", Filters: []string{"filter-card"}, Content: []byte(redContent)}},
			{Time: at(3), Kind: "expire", Session: sess, Agent: "agent-a", Decision: "revoke", Reason: "session expired",
				Channel: "sessions", Chaincode: "sessions-cc", Key: sk, Value: []byte(`{"state":"expired"}`)},
		},
	}
}

func load(t *testing.T, p *replaypack.Pack) *pack.Pack {
	t.Helper()
	z, err := p.Zip()
	if err != nil {
		t.Fatal(err)
	}
	lp, err := pack.Read(bytes.NewReader(z), int64(len(z)))
	if err != nil {
		t.Fatal(err)
	}
	return lp
}

func build(t *testing.T, s replaypack.Spec) *replaypack.Pack {
	t.Helper()
	p, err := replaypack.Build(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func problems(res *checks.Result, name string) string {
	return strings.Join(res.Get(name).Problems, "\n")
}

func TestPEMIdentityRoundTrip(t *testing.T) {
	ca, id := demoIdentity(t)
	p := build(t, demoSpec(id))
	lp := load(t, p)
	res := checks.Run(lp, checks.Options{})
	if !res.OK || res.Warnings != 0 {
		t.Fatalf("want PASS without warnings: %+v", res.Checks)
	}
	if d := res.Get(checks.NameEndorsements).Detail; !strings.HasPrefix(d, "1 of 1 parties") {
		t.Errorf("endorsements detail %q", d)
	}
	if res.Summary.Refused != 1 || res.Summary.Redacted != 1 || res.Summary.Allowed != 1 || res.Summary.Revoked != 1 {
		t.Errorf("summary %+v", res.Summary)
	}

	if res := checks.Run(lp, checks.Options{Pins: []string{replaypack.Fingerprint(ca.Cert)}}); !res.OK {
		t.Fatalf("pinned root should pass: %+v", res.Checks)
	}
	if ca.Fingerprint() != replaypack.Fingerprint(ca.Cert) || ca.Fingerprint() != replaypack.Fingerprint(id.Roots[0]) {
		t.Error("fingerprints disagree")
	}
	other, _ := replaypack.NewCA("Other root", "Other", nb, na)
	res = checks.Run(lp, checks.Options{Pins: []string{other.Fingerprint()}})
	if res.OK || !strings.Contains(problems(res, checks.NameEndorsements), "exporter party DemoMSP is not pinned") {
		t.Fatalf("wrong pin should fail on the exporter: %+v", res.Get(checks.NameEndorsements))
	}

	// Layout and defaults.
	if string(lp.Files["README.txt"]) != replaypack.DefaultReadme {
		t.Error("README.txt is not DefaultReadme")
	}
	if len(lp.Parties) != 1 || lp.Parties[0].DisplayName != "Demo organisation" ||
		strings.Join(lp.Parties[0].Channels, ",") != "monitor,sessions" {
		t.Errorf("parties %+v", lp.Parties)
	}
	if m := lp.Manifest; m.Sources != (replaypack.Sources{Sessions: "ledger", Monitor: "ledger"}) || m.Tenant != "example-tenant" {
		t.Errorf("manifest %+v", m)
	}
	if lp.Order[0] != "manifest.json" {
		t.Errorf("first entry %s", lp.Order[0])
	}
	for i, r := range lp.Records {
		tx := lp.Txs[r.Tx]
		if tx.BlockNumber != uint64(i+1) || tx.CreatorMSP != "DemoMSP" {
			t.Errorf("seq %d tx block %d creator %s", r.Seq, tx.BlockNumber, tx.CreatorMSP)
		}
	}
	if f := lp.Txs[lp.Records[1].Tx].Function; f != "DecisionRecord" {
		t.Errorf("function %q", f)
	}
	// Redaction with explicit Value: the body is the stored bytes, and the
	// hash is over Content.
	if !bytes.Equal(lp.Bodies[3], redValue) {
		t.Errorf("redaction body %s", lp.Bodies[3])
	}
	sum := sha256.Sum256([]byte(redContent))
	rd := lp.Redactions["red-1"]
	if rd == nil || rd.RedactedDataHash != base64.StdEncoding.EncodeToString(sum[:]) || rd.Content == nil {
		t.Fatalf("redaction %+v", rd)
	}

	// Equal files, equal zip.
	a, _ := p.Zip()
	b, _ := p.Zip()
	if !bytes.Equal(a, b) {
		t.Error("zip not deterministic")
	}
}

func TestHashesOnly(t *testing.T) {
	_, id := demoIdentity(t)
	s := demoSpec(id)
	s.HashesOnly = true
	lp := load(t, build(t, s))
	res := checks.Run(lp, checks.Options{})
	if !res.OK || res.Get(checks.NameTransactions).Status != checks.Warn {
		t.Fatalf("want PASS with transactions WARN: %+v", res.Checks)
	}
	if _, ok := lp.Bodies[3]; ok || lp.Redactions["red-1"].Content != nil || !lp.Manifest.HashesOnly {
		t.Error("hashes-only pack carries redacted content")
	}
}

func TestEphemeralIdentity(t *testing.T) {
	a, err := replaypack.NewEphemeralIdentity("DemoMSP", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	b, err := replaypack.NewEphemeralIdentity("DemoMSP", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	if replaypack.Fingerprint(a.Roots[0]) == replaypack.Fingerprint(b.Roots[0]) || a.CertPEM == b.CertPEM {
		t.Fatal("two ephemeral identities share a root")
	}
	if res := checks.Run(load(t, build(t, demoSpec(a))), checks.Options{}); !res.OK {
		t.Fatalf("ephemeral pack should pass: %+v", res.Checks)
	}
}

func TestTampered(t *testing.T) {
	_, id := demoIdentity(t)
	p := build(t, demoSpec(id))
	b := p.Files["records.jsonl"]
	i := bytes.Index(b, []byte("not in badge"))
	b[i] = 'N'
	res := checks.Run(load(t, p), checks.Options{})
	if res.Get(checks.NameManifest).Status != checks.Fail || res.Get(checks.NameChain).Status != checks.Fail {
		t.Fatalf("want manifest+chain FAIL: %+v", res.Checks)
	}
	// An insider holding the key re-signs: manifest passes, the chain still fails.
	if err := p.Resign(); err != nil {
		t.Fatal(err)
	}
	res = checks.Run(load(t, p), checks.Options{})
	for _, c := range res.Checks {
		want := checks.Pass
		switch c.Name {
		case checks.NameChain:
			want = checks.Fail
		case checks.NameSummary:
			want = checks.Info
		}
		if c.Status != want {
			t.Errorf("%s: %s want %s (%v)", c.Name, c.Status, want, c.Problems)
		}
	}
	if !strings.Contains(problems(res, checks.NameChain), "seq 2: hash does not match content") {
		t.Errorf("chain problems %v", res.Get(checks.NameChain).Problems)
	}
}

func TestLeafValidityWindow(t *testing.T) {
	ca, err := replaypack.NewCA("Demo root", "Demo organisation", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	// Leaf valid only from minute 2: entries before it fall outside.
	cert, key, err := ca.Issue("demo exporter", "Demo organisation", at(2), na)
	if err != nil {
		t.Fatal(err)
	}
	id, err := replaypack.NewIdentity("DemoMSP", cert, key, ca.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	res := checks.Run(load(t, build(t, demoSpec(id))), checks.Options{})
	if res.OK || res.Get(checks.NameEndorsements).Status != checks.Fail {
		t.Fatalf("want endorsements FAIL: %+v", res.Checks)
	}
	if got := problems(res, checks.NameEndorsements); strings.Count(got, "not yet valid") != 2 {
		t.Errorf("want the two early transactions out of validity: %s", got)
	}
	if res.Get(checks.NameManifest).Status != checks.Pass {
		t.Errorf("exporter cert is valid at exportedAt: %+v", res.Get(checks.NameManifest))
	}
}

func TestNewIdentityRejects(t *testing.T) {
	ca, err := replaypack.NewCA("Demo root", "Demo organisation", nb, na)
	if err != nil {
		t.Fatal(err)
	}
	cert, key, _ := ca.Issue("a", "Demo organisation", nb, na)
	_, otherKey, _ := ca.Issue("b", "Demo organisation", nb, na)
	foreign, _ := replaypack.NewCA("Other root", "Other", nb, na)

	// SEC 1 keys are accepted as well as PKCS #8.
	blk, _ := pem.Decode([]byte(key))
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(k.(*ecdsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	sec1 := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	for _, kp := range []string{key, sec1} {
		if _, err := replaypack.NewIdentity("DemoMSP", cert, kp, ca.CertPEM); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name, cert, key string
		roots           []string
		want            string
	}{
		{"mismatched key", cert, otherKey, []string{ca.CertPEM}, "does not match"},
		{"foreign root", cert, key, []string{foreign.CertPEM}, "does not chain"},
		{"non-CA root", cert, key, []string{cert}, "not a CA"},
		{"no root", cert, key, nil, "no root"},
		{"bad key", cert, "not a key", []string{ca.CertPEM}, "key"},
		{"bad cert", "not a cert", key, []string{ca.CertPEM}, "certificate"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := replaypack.NewIdentity("DemoMSP", c.cert, c.key, c.roots...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
}

func TestBuildRejects(t *testing.T) {
	_, id := demoIdentity(t)
	other, _ := replaypack.NewEphemeralIdentity("OtherMSP", nb, na)
	cases := map[string]func(*replaypack.Spec){
		"no exporter":        func(s *replaypack.Spec) { s.Exporter = nil },
		"exporter not party": func(s *replaypack.Spec) { s.Exporter = other },
		"time goes back":     func(s *replaypack.Spec) { s.Entries[2].Time = at(-1) },
		"no chaincode":       func(s *replaypack.Spec) { s.Entries[0].Chaincode = "" },
		"duplicate tx":       func(s *replaypack.Spec) { s.Entries[0].TxID, s.Entries[1].TxID = "tx", "tx" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := demoSpec(id)
			mutate(&s)
			if _, err := replaypack.Build(s); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestRecordsRoundTrip(t *testing.T) {
	_, id := demoIdentity(t)
	p := build(t, demoSpec(id))
	recs, err := p.Records()
	if err != nil || len(recs) != 4 {
		t.Fatalf("records %d %v", len(recs), err)
	}
	prev := replaypack.GenesisHash
	for _, r := range recs {
		h, err := replaypack.RecordHash(r)
		if err != nil || h != r["hash"] || r["prevHash"] != prev {
			t.Fatalf("seq %v: chain does not recompute", r["seq"])
		}
		prev = h
	}
	before := append([]byte{}, p.Files["records.jsonl"]...)
	if err := p.WriteRecords(recs, true); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, p.Files["records.jsonl"]) {
		t.Error("rewrite changed records.jsonl")
	}
	var m map[string]any
	if err := json.Unmarshal(p.Files["manifest.json"], &m); err != nil || m["signature"] == nil {
		t.Fatalf("manifest %v", err)
	}
}
