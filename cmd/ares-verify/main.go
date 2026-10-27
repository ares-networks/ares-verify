// Command ares-verify checks a replay pack offline.
//
// Exit codes: 0 every check passed (warnings allowed), 1 a check failed,
// 2 usage error or the pack could not be read.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ares-networks/ares-verify/internal/checks"
	"github.com/ares-networks/ares-verify/internal/fabtx"
	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/internal/parties"
	"github.com/ares-networks/ares-verify/internal/report"
)

// version is set at build time (-X main.version=...).
var version = "dev"

type exitError struct{ code int }

func (e exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

func main() {
	cmd := newRoot(os.Stdout)
	err := cmd.Execute()
	var ee exitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		os.Exit(ee.code)
	default:
		fmt.Fprintln(os.Stderr, "ares-verify:", err)
		os.Exit(2)
	}
}

func newRoot(out io.Writer) *cobra.Command {
	var (
		asJSON     bool
		pins       string
		record     int
		minParties int
	)
	root := &cobra.Command{
		Use:           "ares-verify <pack.zip>",
		Short:         "Check a replay pack offline and print what it proves",
		Version:       version,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := pack.Open(args[0])
			if err != nil {
				return err
			}
			var pinList []string
			for _, s := range strings.Split(pins, ",") {
				if s = strings.TrimSpace(s); s != "" {
					pinList = append(pinList, s)
				}
			}
			res := checks.Run(p, checks.Options{Pins: pinList, MinParties: minParties})
			if record > 0 {
				if err := printRecord(out, p, record, pinList); err != nil {
					return err
				}
			} else if asJSON {
				if err := report.JSON(out, res); err != nil {
					return err
				}
			} else {
				report.Text(out, res)
			}
			if !res.OK {
				return exitError{1}
			}
			return nil
		},
	}
	root.Flags().BoolVar(&asJSON, "json", false, "machine-readable report")
	root.Flags().StringVar(&pins, "pin", "", "comma-separated party root fingerprints (hex SHA-256) that must be trusted")
	root.Flags().IntVar(&record, "record", 0, "print one record with its transaction and endorsements")
	root.Flags().IntVar(&minParties, "min-parties", 1, "distinct parties required to endorse each transaction")
	root.AddCommand(&cobra.Command{
		Use:   "explain",
		Short: "What each check proves, and what it does not",
		Args:  cobra.NoArgs,
		Run:   func(*cobra.Command, []string) { fmt.Fprint(out, explainText) },
	})
	return root
}

func printRecord(out io.Writer, p *pack.Pack, seq int, pins []string) error {
	if p.RecordsErr != nil {
		return p.RecordsErr
	}
	var rec *pack.Record
	for i := range p.Records {
		if p.Records[i].Seq == seq {
			rec = &p.Records[i]
			break
		}
	}
	if rec == nil {
		return fmt.Errorf("no record with seq %d", seq)
	}
	b, _ := json.MarshalIndent(rec.Raw, "", "  ")
	fmt.Fprintf(out, "record #%d\n%s\n", seq, b)
	if rec.Tx == "" {
		fmt.Fprintln(out, "transaction: none (unanchored)")
		return nil
	}
	t, ok := p.Txs[rec.Tx]
	if !ok {
		fmt.Fprintf(out, "transaction %s: not in pack\n", rec.Tx)
		return nil
	}
	fmt.Fprintf(out, "transaction %s\n  channel %s, block %d, %s, %s, function %s, creator %s\n",
		t.TxID, t.Channel, t.BlockNumber, t.Timestamp, t.ValidationCode, t.Function, t.CreatorMSP)
	fmt.Fprintln(out, "  (block, time, validation code and function are exporter labels, not signed)")
	if t.Withheld {
		fmt.Fprintln(out, "  withheld (hashes-only export): endorsements not verifiable")
		return nil
	}
	prp, err := base64.StdEncoding.DecodeString(t.ProposalResponsePayload)
	if err != nil {
		fmt.Fprintln(out, "  proposal response payload is not base64")
		return nil
	}
	set, _ := parties.Build(p.Parties, pins)
	at, err := time.Parse(time.RFC3339Nano, t.Timestamp)
	if err != nil {
		at = time.Now()
	}
	fmt.Fprintf(out, "endorsements (%d)\n", len(t.Endorsements))
	for i, e := range t.Endorsements {
		eb, _ := base64.StdEncoding.DecodeString(e.Endorser)
		sb, _ := base64.StdEncoding.DecodeString(e.Signature)
		en, err := fabtx.VerifyEndorsement(prp, eb, sb)
		msp, fp := "?", "?"
		if en != nil {
			msp, fp = en.MSPID, parties.Fingerprint(en.Cert)
		}
		status := "valid"
		if err != nil {
			status = "INVALID: " + err.Error()
		} else if err := set.VerifyChain(en.MSPID, en.Cert, at); err != nil {
			status = "INVALID: " + err.Error()
		}
		fmt.Fprintf(out, "  %d. %s  cert %s  %s\n", i+1, msp, fp, status)
	}
	return nil
}

const explainText = `What ares-verify checks

manifest       Every file in the pack is listed with its SHA-256 and size, nothing
               is added or missing, and the exporter signed that list. The
               exporter's certificate chains to one of the parties.
               Proves: the pack is the one the exporter produced.

chain          Records are numbered 1..n without gaps, times never go backwards,
               and each record's hash covers its content and the previous hash.
               Proves: no record was edited, removed, inserted or reordered after
               export (by anyone without the exporter's key).

transactions   Each record points at a ledger transaction, and the write that
               transaction made to the record's key has exactly the record's
               value hash. Records without a transaction, or whose transaction is
               withheld in a hashes-only export, are reported as warnings.
               Proves: the record is what the ledger stored, not a summary.

endorsements   Each transaction's endorsement signatures verify, each endorser's
               certificate chains to its organisation's root, and at least
               --min-parties distinct organisations endorsed it ("N of M parties").
               With --pin, only organisations whose root fingerprint you pinned
               (for example from the operator's published trust page) count.
               Proves: those organisations confirmed the write with their own
               keys. Without --pin, the roots come from the pack itself; the
               report lists each root's fingerprint so you can compare it with
               a source you trust. Withheld transactions (hashes-only) have no
               endorsements and are counted separately.

redactions     Stripped content, where included, matches the hash the ledger
               stored. Hash-only redactions are listed.
               Proves: what was removed, or that it was removed, without
               disclosing it.

summary        Counts by decision and every refusal with its reason.

What a PASS does not prove

- That the agents' outputs were correct or appropriate.
- That no call happened outside the recording path.
- That a transaction was committed in a given block: block number, time and
  validation code are exporter labels, not signed by the ordering service in
  this version.
- That the pack holds every record that exists. It proves the included
  records were not altered or invented.
`
