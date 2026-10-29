// Package chain computes and checks the record hash chain (FORMAT.md §4).
package chain

import (
	"fmt"
	"time"

	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/pkg/replaypack"
)

// Genesis is the prevHash of record 1.
var Genesis = replaypack.GenesisHash

// Hash returns hex SHA-256( JCS(record without "hash") || prevHash ).
// prevHash is taken from the record itself.
func Hash(raw map[string]any) (string, error) { return replaypack.RecordHash(raw) }

// Result of a chain check.
type Result struct {
	Count    int
	First    time.Time
	Last     time.Time
	Problems []string
}

// Verify checks seq contiguity, time order and every link.
func Verify(recs []pack.Record) Result {
	res := Result{Count: len(recs)}
	prev := Genesis
	var prevT time.Time
	prevSeq := 0
	for i, r := range recs {
		// Compare with the previous record's own seq, so one gap is one line.
		if want := prevSeq + 1; r.Seq != want {
			res.Problems = append(res.Problems, fmt.Sprintf("line %d: seq %d, expected %d (record missing or reordered)", r.Line, r.Seq, want))
		}
		prevSeq = r.Seq
		t, err := time.Parse(time.RFC3339Nano, r.Time)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("seq %d: bad time %q", r.Seq, r.Time))
		} else {
			if i == 0 {
				res.First = t
			}
			if !prevT.IsZero() && t.Before(prevT) {
				res.Problems = append(res.Problems, fmt.Sprintf("seq %d: time %s before previous record", r.Seq, r.Time))
			}
			prevT, res.Last = t, t
		}
		if r.PrevHash != prev {
			res.Problems = append(res.Problems, fmt.Sprintf("seq %d: prevHash does not match previous record's hash", r.Seq))
		}
		h, err := Hash(r.Raw)
		if err != nil {
			res.Problems = append(res.Problems, fmt.Sprintf("seq %d: cannot canonicalise: %v", r.Seq, err))
		} else if h != r.Hash {
			res.Problems = append(res.Problems, fmt.Sprintf("seq %d: hash does not match content (record edited)", r.Seq))
		}
		prev = r.Hash
	}
	return res
}
