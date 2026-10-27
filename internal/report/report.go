// Package report renders a check result for people (text) or machines (JSON).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"

	"github.com/ares-networks/ares-verify/internal/checks"
)

// Text writes the human report. Problems beyond the first few per check are
// summarised; --json carries all of them.
func Text(w io.Writer, r *checks.Result) {
	fmt.Fprintf(w, "ares-verify %s\n", filepath.Base(r.Pack))
	for _, c := range r.Checks {
		status := c.Status
		if status == checks.Info {
			status = ""
		}
		fmt.Fprintf(w, "  %-15s %-5s %s\n", c.Name, status, c.Detail)
		const show = 5
		for i, p := range c.Problems {
			if i == 0 && p == c.Detail {
				continue
			}
			if i >= show {
				fmt.Fprintf(w, "  %-15s %-5s ... %d more (use --json)\n", "", "", len(c.Problems)-show)
				break
			}
			fmt.Fprintf(w, "  %-15s %-5s %s\n", "", "", p)
		}
	}
	for _, f := range r.Refusals {
		fmt.Fprintf(w, "  %-15s %-15s reason: %s\n", fmt.Sprintf("refused #%d", f.Seq), f.Action, f.Reason)
	}
	// Root fingerprints computed from the pack, so a recipient can compare
	// them with the operator's published values and pass them to --pin.
	for _, pt := range r.Parties {
		for _, fp := range pt.Fingerprints {
			mark := ""
			if pt.Pinned {
				mark = "  pinned"
			}
			fmt.Fprintf(w, "  %-15s %-5s %s %s%s\n", "root", "", pt.MSPID, fp, mark)
		}
	}
	if r.OK {
		fmt.Fprintln(w, "result: PASS")
	} else {
		fmt.Fprintln(w, "result: FAIL")
	}
}

// JSON writes the machine report.
func JSON(w io.Writer, r *checks.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
