package chain

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ares-networks/ares-verify/internal/pack"
)

func build(t *testing.T, n int) []byte {
	t.Helper()
	var sb strings.Builder
	prev := Genesis
	for i := 1; i <= n; i++ {
		raw := map[string]any{
			"seq": json.Number(itoa(i)), "time": "2026-01-01T00:00:0" + itoa(i) + "Z",
			"kind": "session-write", "session": "s\u0000x", "prevHash": prev,
		}
		h, err := Hash(raw)
		if err != nil {
			t.Fatal(err)
		}
		raw["hash"] = h
		b, _ := json.Marshal(raw)
		sb.Write(b)
		sb.WriteByte('\n')
		prev = h
	}
	return []byte(sb.String())
}

func itoa(i int) string { return string(rune('0' + i)) }

func TestVerify(t *testing.T) {
	good := build(t, 3)
	cases := []struct {
		name    string
		mutate  func(string) string
		problem string
	}{
		{"intact", func(s string) string { return s }, ""},
		{"edited", func(s string) string {
			return strings.Replace(s, `"kind":"session-write"`, `"kind":"session-wrote"`, 1)
		}, "record edited"},
		{"dropped", func(s string) string {
			l := strings.SplitAfter(s, "\n")
			return l[0] + l[2]
		}, "seq 3, expected 2"},
		{"reordered", func(s string) string {
			l := strings.SplitAfter(s, "\n")
			return l[1] + l[0] + l[2]
		}, "expected 1"},
		{"extra member covered", func(s string) string { return strings.Replace(s, `{`, `{"x":1,`, 1) }, "record edited"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			recs, err := pack.ParseRecords([]byte(c.mutate(string(good))))
			if err != nil {
				t.Fatal(err)
			}
			res := Verify(recs)
			if c.problem == "" {
				if len(res.Problems) != 0 {
					t.Fatalf("unexpected problems: %v", res.Problems)
				}
				return
			}
			if !strings.Contains(strings.Join(res.Problems, "\n"), c.problem) {
				t.Fatalf("want %q in %v", c.problem, res.Problems)
			}
		})
	}
}
