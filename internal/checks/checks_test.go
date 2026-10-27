package checks_test

import (
	"strings"
	"testing"

	"github.com/ares-networks/ares-verify/internal/checks"
	"github.com/ares-networks/ares-verify/internal/fixtures"
	"github.com/ares-networks/ares-verify/internal/parties"
)

func TestVariants(t *testing.T) {
	cases := []struct {
		variant string
		ok      bool
		status  map[string]string // check -> status; unlisted checks must PASS (summary INFO)
		problem string            // substring expected in the failing check
	}{
		{"valid", true, nil, ""},
		{"hashes-only", true, map[string]string{checks.NameTransactions: checks.Warn}, ""},
		{"tampered-record", false, map[string]string{checks.NameChain: checks.Fail}, "seq 5: hash does not match content"},
		{"dropped-record", false, map[string]string{checks.NameChain: checks.Fail}, "seq 6, expected 5"},
		{"missing-endorsement", false, map[string]string{checks.NameEndorsements: checks.Fail}, "0 of 2 parties, need 1"},
		{"swapped-party-cert", false, map[string]string{checks.NameManifest: checks.Fail, checks.NameEndorsements: checks.Fail}, "does not chain to Org1MSP"},
	}
	for _, c := range cases {
		t.Run(c.variant, func(t *testing.T) {
			fp, err := fixtures.BuildVariant(c.variant)
			if err != nil {
				t.Fatal(err)
			}
			p, err := fp.Load(c.variant + ".zip")
			if err != nil {
				t.Fatal(err)
			}
			res := checks.Run(p, checks.Options{})
			if res.OK != c.ok {
				t.Fatalf("ok=%v want %v: %+v", res.OK, c.ok, res.Checks)
			}
			var failText []string
			for _, ck := range res.Checks {
				want := checks.Pass
				if ck.Name == checks.NameSummary {
					want = checks.Info
				}
				if s, ok := c.status[ck.Name]; ok {
					want = s
				}
				if ck.Status != want {
					t.Errorf("%s: status %s want %s (%s; %v)", ck.Name, ck.Status, want, ck.Detail, ck.Problems)
				}
				failText = append(failText, ck.Problems...)
			}
			if c.problem != "" && !strings.Contains(strings.Join(failText, "\n"), c.problem) {
				t.Errorf("want problem %q, got %v", c.problem, failText)
			}
		})
	}
}

func TestValidCounts(t *testing.T) {
	fp, err := fixtures.BuildVariant("valid")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := fp.Load("valid.zip")
	res := checks.Run(p, checks.Options{MinParties: 2})
	if !res.OK {
		t.Fatalf("min 2 should pass: %+v", res.Checks)
	}
	if d := res.Get(checks.NameEndorsements).Detail; !strings.HasPrefix(d, "2 of 2 parties") {
		t.Errorf("endorsements detail %q", d)
	}
	if res.Summary.Refused != 1 || res.Summary.Redacted != 2 || res.Summary.Revoked != 1 || len(res.Refusals) != 1 {
		t.Errorf("summary %+v refusals %+v", res.Summary, res.Refusals)
	}
	if d := res.Get(checks.NameRedactions).Detail; d != "2 records, 0 hashes-only" {
		t.Errorf("redactions detail %q", d)
	}
	if res := checks.Run(p, checks.Options{MinParties: 3}); res.OK {
		t.Error("min 3 should fail with 2 parties")
	}
}

func TestPins(t *testing.T) {
	s, err := fixtures.DefaultSpec()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := fixtures.Build(s)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := fp.Load("pins.zip")
	both := []string{parties.Fingerprint(s.Orgs[0].CACert), parties.Fingerprint(s.Orgs[1].CACert)}
	if res := checks.Run(p, checks.Options{Pins: both, MinParties: 2}); !res.OK {
		t.Fatalf("both pinned should pass: %+v", res.Checks)
	}
	// Pin only org2: exporter (org1) not pinned -> FAIL.
	res := checks.Run(p, checks.Options{Pins: both[1:]})
	if res.OK || !strings.Contains(strings.Join(res.Get(checks.NameEndorsements).Problems, "\n"), "exporter party Org1MSP is not pinned") {
		t.Fatalf("want exporter-not-pinned failure: %+v", res.Get(checks.NameEndorsements))
	}
	// Unknown pin: nothing counts.
	if res := checks.Run(p, checks.Options{Pins: []string{strings.Repeat("ab", 32)}}); res.OK {
		t.Fatal("unknown pin should fail")
	}
}

func TestUnsignedEditFailsManifest(t *testing.T) {
	fp, err := fixtures.BuildVariant("valid")
	if err != nil {
		t.Fatal(err)
	}
	b := fp.Files["records.jsonl"]
	i := strings.Index(string(b), "outside badge")
	b[i] = 'O'
	p, _ := fp.Load("edited.zip")
	res := checks.Run(p, checks.Options{})
	if res.Get(checks.NameManifest).Status != checks.Fail || res.Get(checks.NameChain).Status != checks.Fail {
		t.Fatalf("want manifest+chain FAIL: %+v", res.Checks)
	}
	if !strings.Contains(strings.Join(res.Get(checks.NameManifest).Problems, "\n"), "records.jsonl SHA-256 does not match manifest") {
		t.Fatalf("%+v", res.Get(checks.NameManifest))
	}
}

func TestBodyAndWriteMismatch(t *testing.T) {
	fp, err := fixtures.BuildVariant("valid")
	if err != nil {
		t.Fatal(err)
	}
	fp.Files["bodies/1.json"] = []byte(`{"sessionId":"other"}`)
	recs, _ := fp.Records()
	recs[1]["valueHash"] = strings.Repeat("0", 64)
	if err := fp.WriteRecords(recs, true); err != nil {
		t.Fatal(err)
	}
	if err := fp.Resign(); err != nil {
		t.Fatal(err)
	}
	p, _ := fp.Load("x.zip")
	res := checks.Run(p, checks.Options{})
	got := strings.Join(res.Get(checks.NameTransactions).Problems, "\n")
	for _, want := range []string{"seq 1: bodies/1.json does not match valueHash", "seq 2: write-set value in tx", "seq 2: bodies/2.json does not match valueHash"} {
		if !strings.Contains(got, want) {
			t.Errorf("want %q in %s", want, got)
		}
	}
}

func TestWithheldNotCountedAsEndorsed(t *testing.T) {
	fp, err := fixtures.BuildVariant("hashes-only")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := fp.Load("hashes-only.zip")
	res := checks.Run(p, checks.Options{})
	d := res.Get(checks.NameEndorsements).Detail
	if !strings.Contains(d, "on every endorsed transaction") || !strings.HasSuffix(d, "; 1 withheld (no endorsements)") {
		t.Errorf("endorsements detail %q", d)
	}
	if res.Result != checks.Pass || res.Warnings != 1 {
		t.Errorf("result %s warnings %d, want PASS 1", res.Result, res.Warnings)
	}

	fp, _ = fixtures.BuildVariant("valid")
	p, _ = fp.Load("valid.zip")
	res = checks.Run(p, checks.Options{})
	if d := res.Get(checks.NameEndorsements).Detail; !strings.Contains(d, "on every transaction (") || strings.Contains(d, "withheld") {
		t.Errorf("valid endorsements detail %q", d)
	}
	if res.Result != checks.Pass || res.Warnings != 0 {
		t.Errorf("result %s warnings %d, want PASS 0", res.Result, res.Warnings)
	}

	fp, _ = fixtures.BuildVariant("tampered-record")
	p, _ = fp.Load("tampered-record.zip")
	if res := checks.Run(p, checks.Options{}); res.Result != checks.Fail || res.OK {
		t.Errorf("tampered: result %s ok %v", res.Result, res.OK)
	}
}

func TestPartiesReportComputedFingerprints(t *testing.T) {
	s, err := fixtures.DefaultSpec()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := fixtures.Build(s)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := fp.Load("parties.zip")
	want := map[string]string{
		s.Orgs[0].MSPID: parties.Fingerprint(s.Orgs[0].CACert),
		s.Orgs[1].MSPID: parties.Fingerprint(s.Orgs[1].CACert),
	}
	res := checks.Run(p, checks.Options{Pins: []string{want[s.Orgs[0].MSPID]}})
	if len(res.Parties) != 2 {
		t.Fatalf("parties %+v", res.Parties)
	}
	for _, pt := range res.Parties {
		if len(pt.Fingerprints) != 1 || pt.Fingerprints[0] != want[pt.MSPID] {
			t.Errorf("%s fingerprints %v want %s", pt.MSPID, pt.Fingerprints, want[pt.MSPID])
		}
		if len(pt.Channels) == 0 {
			t.Errorf("%s has no channels", pt.MSPID)
		}
		if pt.Pinned != (pt.MSPID == s.Orgs[0].MSPID) {
			t.Errorf("%s pinned=%v", pt.MSPID, pt.Pinned)
		}
	}
	// What the report prints must round-trip through --pin.
	var all []string
	for _, pt := range res.Parties {
		all = append(all, pt.Fingerprints...)
	}
	if res := checks.Run(p, checks.Options{Pins: all, MinParties: 2}); !res.OK {
		t.Fatalf("pinning the reported fingerprints should pass: %+v", res.Checks)
	}
}
