package fixtures

import (
	"strings"
	"testing"
)

// The wrapper keeps the fixture conventions the committed testdata has.
func TestFixtureConventions(t *testing.T) {
	fp, err := BuildVariant("valid")
	if err != nil {
		t.Fatal(err)
	}
	p, err := fp.Load("valid.zip")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range p.Records {
		tx := p.Txs[r.Tx]
		if want := "fixture" + strings.ReplaceAll(r.Kind, "-", ""); tx.Function != want {
			t.Errorf("seq %d function %q want %q", r.Seq, tx.Function, want)
		}
		if tx.BlockNumber != uint64(10+r.Seq) || tx.CreatorMSP != "Org1MSP" {
			t.Errorf("seq %d block %d creator %s", r.Seq, tx.BlockNumber, tx.CreatorMSP)
		}
	}
	for _, pt := range p.Parties {
		if pt.DisplayName != pt.MSPID || len(pt.Channels) != 2 {
			t.Errorf("party %+v", pt)
		}
	}
	if string(p.Files["README.txt"]) != readme {
		t.Error("README.txt changed")
	}
}
