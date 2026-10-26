package fabtx_test

import (
	"testing"

	"github.com/ares-networks/ares-verify/internal/fabtx"
	"github.com/ares-networks/ares-verify/internal/fixtures"
)

func TestDecodeAndEndorse(t *testing.T) {
	org, err := fixtures.NewOrg("Org1MSP")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := fixtures.NewOrg("Org2MSP")
	prp, err := fixtures.BuildPRP("cc", "tx1", []fixtures.KVWrite{{Key: "\x00k\x00", Value: []byte("v")}, {Key: "gone", IsDelete: true}})
	if err != nil {
		t.Fatal(err)
	}
	a, err := fabtx.DecodePRP(prp)
	if err != nil {
		t.Fatal(err)
	}
	if w, ok := a.Find("\x00k\x00"); !ok || string(w.Value) != "v" {
		t.Fatalf("write not found: %+v", a)
	}
	if w, ok := a.Find("gone"); !ok || !w.IsDelete {
		t.Fatal("delete not found")
	}
	eb, sig, err := org.Endorse(prp)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name         string
		prp, eb, sig []byte
		ok           bool
	}{
		{"valid", prp, eb, sig, true},
		{"prp changed", append(append([]byte{}, prp...), 0), eb, sig, false},
		{"other identity", prp, other.Identity(), sig, false},
		{"garbage sig", prp, eb, []byte{1, 2, 3}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			en, err := fabtx.VerifyEndorsement(c.prp, c.eb, c.sig)
			if (err == nil) != c.ok {
				t.Fatalf("err=%v want ok=%v", err, c.ok)
			}
			if c.ok && en.MSPID != "Org1MSP" {
				t.Fatalf("msp %s", en.MSPID)
			}
		})
	}
	if _, err := fabtx.DecodePRP([]byte("not proto")); err == nil {
		t.Fatal("garbage PRP should not decode")
	}
}
