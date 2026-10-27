// Package checks runs the six pack checks of FORMAT.md §8, in order.
package checks

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ares-networks/ares-verify/internal/canon"
	"github.com/ares-networks/ares-verify/internal/chain"
	"github.com/ares-networks/ares-verify/internal/fabtx"
	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/internal/parties"
)

// Statuses.
const (
	Pass = "PASS"
	Fail = "FAIL"
	Warn = "WARN"
	Info = "INFO"
)

// Check names, in report order.
const (
	NameManifest     = "manifest"
	NameChain        = "chain"
	NameTransactions = "transactions"
	NameEndorsements = "endorsements"
	NameRedactions   = "redactions"
	NameSummary      = "summary"
)

// Options tune the run.
type Options struct {
	Pins       []string
	MinParties int
}

type Check struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
	Problems []string `json:"problems,omitempty"`
}

type Summary struct {
	Records  int `json:"records"`
	Allowed  int `json:"allowed"`
	Narrowed int `json:"narrowed"`
	Refused  int `json:"refused"`
	Redacted int `json:"redacted"`
	Human    int `json:"human"`
	Revoked  int `json:"revoked"`
	Recorded int `json:"recorded"`
}

type Refusal struct {
	Seq    int    `json:"seq"`
	Time   string `json:"time"`
	Agent  string `json:"agent"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// PartyInfo is one organisation as the verifier sees it. Fingerprints are
// computed from the root certificates in the pack, never copied from the
// pack's own fingerprint list, so a recipient can compare them with a source
// they trust before pinning.
type PartyInfo struct {
	MSPID        string   `json:"mspId"`
	DisplayName  string   `json:"displayName,omitempty"`
	Channels     []string `json:"channels"`
	Fingerprints []string `json:"rootFingerprints"`
	Pinned       bool     `json:"pinned"`
}

type Result struct {
	Pack     string      `json:"pack"`
	Result   string      `json:"result"`   // PASS or FAIL, as the text report's last line
	Warnings int         `json:"warnings"` // checks with status WARN; they do not fail the pack
	Checks   []Check     `json:"checks"`
	Summary  Summary     `json:"summary"`
	Refusals []Refusal   `json:"refusals"`
	Parties  []PartyInfo `json:"parties"`
	OK       bool        `json:"ok"`
}

// Get returns the check with name n.
func (r *Result) Get(n string) *Check {
	for i := range r.Checks {
		if r.Checks[i].Name == n {
			return &r.Checks[i]
		}
	}
	return nil
}

func finish(c Check, okDetail string) Check {
	if len(c.Problems) > 0 {
		c.Status = Fail
		if c.Detail == "" {
			c.Detail = c.Problems[0]
		}
		return c
	}
	if c.Status == "" {
		c.Status = Pass
	}
	if c.Detail == "" {
		c.Detail = okDetail
	}
	return c
}

// Run verifies p.
func Run(p *pack.Pack, opt Options) *Result {
	if opt.MinParties < 1 {
		opt.MinParties = 1
	}
	res := &Result{Pack: p.Name, Refusals: []Refusal{}}
	set, partyProblems := parties.Build(p.Parties, opt.Pins)
	if p.PartiesErr != nil {
		partyProblems = append([]string{p.PartiesErr.Error()}, partyProblems...)
	}

	res.Checks = append(res.Checks, checkManifest(p, set))
	res.Checks = append(res.Checks, checkChain(p))
	txCheck, prps := checkTransactions(p)
	res.Checks = append(res.Checks, txCheck)
	res.Checks = append(res.Checks, checkEndorsements(p, set, partyProblems, prps, opt))
	res.Checks = append(res.Checks, checkRedactions(p))
	sum, refusals := summarise(p)
	res.Summary, res.Refusals = sum, refusals
	res.Checks = append(res.Checks, Check{Name: NameSummary, Status: Info, Detail: fmt.Sprintf(
		"%d allowed, %d refused, %d redacted, %d sent to a human, %d revoked",
		sum.Allowed, sum.Refused, sum.Redacted, sum.Human, sum.Revoked)})

	res.Parties = partyInfo(set)
	res.OK = true
	for _, c := range res.Checks {
		switch c.Status {
		case Fail:
			res.OK = false
		case Warn:
			res.Warnings++
		}
	}
	res.Result = Pass
	if !res.OK {
		res.Result = Fail
	}
	return res
}

func partyInfo(set *parties.Set) []PartyInfo {
	out := make([]PartyInfo, 0, len(set.Order))
	for _, id := range set.Order {
		pt := set.ByMSP[id]
		chs := make([]string, 0, len(pt.Channels))
		for ch := range pt.Channels {
			chs = append(chs, ch)
		}
		sort.Strings(chs)
		out = append(out, PartyInfo{MSPID: pt.MSPID, DisplayName: pt.DisplayName, Channels: chs,
			Fingerprints: append([]string{}, pt.Fingerprints...), Pinned: pt.Pinned})
	}
	return out
}

func checkManifest(p *pack.Pack, set *parties.Set) Check {
	c := Check{Name: NameManifest}
	if p.ManifestErr != nil {
		c.Problems = append(c.Problems, p.ManifestErr.Error())
		return finish(c, "")
	}
	m := p.Manifest
	if m.PackVersion != 1 {
		c.Problems = append(c.Problems, fmt.Sprintf("packVersion %d not supported (want 1)", m.PackVersion))
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if f.Path == "manifest.json" {
			c.Problems = append(c.Problems, "manifest lists itself")
			continue
		}
		if listed[f.Path] {
			c.Problems = append(c.Problems, fmt.Sprintf("%s listed twice", f.Path))
			continue
		}
		listed[f.Path] = true
		b, ok := p.Files[f.Path]
		if !ok {
			c.Problems = append(c.Problems, fmt.Sprintf("%s listed but missing", f.Path))
			continue
		}
		if int64(len(b)) != f.Size {
			c.Problems = append(c.Problems, fmt.Sprintf("%s size %d, manifest says %d", f.Path, len(b), f.Size))
		}
		s := sha256.Sum256(b)
		if hex.EncodeToString(s[:]) != strings.ToLower(f.SHA256) {
			c.Problems = append(c.Problems, fmt.Sprintf("%s SHA-256 does not match manifest", f.Path))
		}
	}
	for _, n := range p.Order {
		if n != "manifest.json" && !listed[n] {
			c.Problems = append(c.Problems, fmt.Sprintf("%s present but not in manifest", n))
		}
	}
	for _, req := range []string{"records.jsonl", "parties.json", "README.txt"} {
		if _, ok := p.Files[req]; !ok {
			c.Problems = append(c.Problems, fmt.Sprintf("required file %s missing", req))
		}
	}

	sigOK := false
	cert, err := parties.ParseCert(m.Exporter.CertPEM)
	if err != nil {
		c.Problems = append(c.Problems, "exporter certificate: "+err.Error())
	} else if m.Signature.Alg != "ECDSA-P256-SHA256" {
		c.Problems = append(c.Problems, fmt.Sprintf("signature alg %q not supported", m.Signature.Alg))
	} else if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		c.Problems = append(c.Problems, "exporter key is not ECDSA")
	} else if sig, err := base64.StdEncoding.DecodeString(m.Signature.Value); err != nil {
		c.Problems = append(c.Problems, "signature is not base64")
	} else {
		unsigned := make(map[string]any, len(p.ManifestRaw))
		for k, v := range p.ManifestRaw {
			if k != "signature" {
				unsigned[k] = v
			}
		}
		b, err := canon.Encode(unsigned)
		if err != nil {
			c.Problems = append(c.Problems, "manifest cannot be canonicalised: "+err.Error())
		} else {
			d := sha256.Sum256(b)
			if ecdsa.VerifyASN1(pub, d[:], sig) {
				sigOK = true
			} else {
				c.Problems = append(c.Problems, "exporter signature does not verify")
			}
		}
	}
	if cert != nil {
		at := parseTime(m.ExportedAt)
		if err := set.VerifyChain(m.Exporter.MSPID, cert, at); err != nil {
			c.Problems = append(c.Problems, "exporter "+err.Error())
		}
	}
	detail := fmt.Sprintf("%d files", len(m.Files))
	if sigOK {
		detail += ", exporter sig ok"
	}
	return finish(c, detail)
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Now()
	}
	return t
}

func checkChain(p *pack.Pack) Check {
	c := Check{Name: NameChain}
	if p.RecordsErr != nil {
		c.Problems = append(c.Problems, p.RecordsErr.Error())
		return finish(c, "")
	}
	if len(p.Records) == 0 {
		c.Status = Warn
		return finish(c, "no records")
	}
	r := chain.Verify(p.Records)
	c.Problems = r.Problems
	return finish(c, fmt.Sprintf("%d records, contiguous, %s", r.Count, span(r.First, r.Last)))
}

func span(a, b time.Time) string {
	a, b = a.UTC(), b.UTC()
	first := a.Format("2006-01-02T15:04Z")
	if a.Format("2006-01-02") == b.Format("2006-01-02") {
		return first + " .. " + b.Format("15:04Z")
	}
	return first + " .. " + b.Format("2006-01-02T15:04Z")
}

// prpOK maps txId to the decoded PRP bytes for transactions that passed
// check 3, so check 4 looks only at what anchors a record.
type prpOK map[string][]byte

func checkTransactions(p *pack.Pack) (Check, prpOK) {
	c := Check{Name: NameTransactions}
	ok := prpOK{}
	if p.RecordsErr != nil {
		c.Problems = append(c.Problems, "records unreadable")
		return finish(c, ""), ok
	}
	decoded := map[string]*fabtx.Action{}
	decodeErr := map[string]error{}
	var matched, anchored, unanchored, withheld int
	for _, r := range p.Records {
		if body, has := p.Bodies[r.Seq]; has {
			s := sha256.Sum256(body)
			if hex.EncodeToString(s[:]) != r.ValueHash {
				c.Problems = append(c.Problems, fmt.Sprintf("seq %d: bodies/%d.json does not match valueHash", r.Seq, r.Seq))
			}
		}
		if r.Tx == "" {
			unanchored++
			continue
		}
		anchored++
		t, has := p.Txs[r.Tx]
		if !has {
			if err := p.TxErr[r.Tx]; err != nil {
				c.Problems = append(c.Problems, fmt.Sprintf("seq %d: tx/%s.json unreadable: %v", r.Seq, r.Tx, err))
			} else {
				c.Problems = append(c.Problems, fmt.Sprintf("seq %d: tx/%s.json missing", r.Seq, r.Tx))
			}
			continue
		}
		if t.TxID != r.Tx {
			c.Problems = append(c.Problems, fmt.Sprintf("seq %d: tx/%s.json holds txId %s", r.Seq, r.Tx, t.TxID))
			continue
		}
		if t.Channel != r.Channel {
			c.Problems = append(c.Problems, fmt.Sprintf("seq %d: record channel %s, transaction channel %s", r.Seq, r.Channel, t.Channel))
			continue
		}
		if t.Withheld {
			withheld++
			continue
		}
		a, done := decoded[r.Tx]
		if !done && decodeErr[r.Tx] == nil {
			prp, err := base64.StdEncoding.DecodeString(t.ProposalResponsePayload)
			if err == nil {
				a, err = fabtx.DecodePRP(prp)
			}
			if err != nil {
				decodeErr[r.Tx] = err
			} else {
				decoded[r.Tx] = a
				ok[r.Tx] = prp
			}
		}
		if err := decodeErr[r.Tx]; err != nil {
			c.Problems = append(c.Problems, fmt.Sprintf("seq %d: tx %s does not decode: %v", r.Seq, r.Tx, err))
			continue
		}
		w, found := a.Find(r.Key)
		switch {
		case !found:
			c.Problems = append(c.Problems, fmt.Sprintf("seq %d: tx %s has no write to the record's key", r.Seq, r.Tx))
		case r.ValueHash == "":
			if !w.IsDelete {
				c.Problems = append(c.Problems, fmt.Sprintf("seq %d: record says delete, tx %s writes a value", r.Seq, r.Tx))
			} else {
				matched++
			}
		default:
			s := sha256.Sum256(w.Value)
			if w.IsDelete || hex.EncodeToString(s[:]) != r.ValueHash {
				c.Problems = append(c.Problems, fmt.Sprintf("seq %d: write-set value in tx %s does not match the record", r.Seq, r.Tx))
			} else {
				matched++
			}
		}
	}
	detail := fmt.Sprintf("%d/%d write sets match", matched, len(p.Records))
	if withheld > 0 {
		detail += fmt.Sprintf(", %d withheld (hashes-only, not verifiable)", withheld)
	}
	if unanchored > 0 {
		detail += fmt.Sprintf(", %d unanchored (no transaction)", unanchored)
	}
	if withheld > 0 || unanchored > 0 {
		c.Status = Warn
	}
	return finish(c, detail), ok
}

func checkEndorsements(p *pack.Pack, set *parties.Set, partyProblems []string, prps prpOK, opt Options) Check {
	c := Check{Name: NameEndorsements, Problems: append([]string{}, partyProblems...)}
	pinned := len(opt.Pins) > 0
	if pinned && p.Manifest != nil {
		if pt, ok := set.ByMSP[p.Manifest.Exporter.MSPID]; !ok || !pt.Pinned {
			c.Problems = append(c.Problems, fmt.Sprintf("exporter party %s is not pinned", p.Manifest.Exporter.MSPID))
		}
	}
	ids := make([]string, 0, len(prps))
	for id := range prps {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	minN, maxN, maxM := -1, 0, 0
	used := map[string]bool{}
	for _, id := range ids {
		t := p.Txs[id]
		prp := prps[id]
		at := parseTime(t.Timestamp)
		m := set.OnChannel(t.Channel)
		got := map[string]bool{}
		for i, e := range t.Endorsements {
			eb, err1 := base64.StdEncoding.DecodeString(e.Endorser)
			sb, err2 := base64.StdEncoding.DecodeString(e.Signature)
			if err1 != nil || err2 != nil {
				c.Problems = append(c.Problems, fmt.Sprintf("tx %s endorsement %d: not base64", id, i+1))
				continue
			}
			en, err := fabtx.VerifyEndorsement(prp, eb, sb)
			if err != nil {
				c.Problems = append(c.Problems, fmt.Sprintf("tx %s endorsement %d: %v", id, i+1, err))
				continue
			}
			if err := set.VerifyChain(en.MSPID, en.Cert, at); err != nil {
				c.Problems = append(c.Problems, fmt.Sprintf("tx %s endorsement %d: %v", id, i+1, err))
				continue
			}
			pt := set.ByMSP[en.MSPID]
			if !pt.Channels[t.Channel] {
				c.Problems = append(c.Problems, fmt.Sprintf("tx %s endorsement %d: %s is not a party on channel %s", id, i+1, en.MSPID, t.Channel))
				continue
			}
			if pinned && !pt.Pinned {
				continue
			}
			got[en.MSPID] = true
			used[en.MSPID] = true
		}
		n := len(got)
		if n < opt.MinParties {
			c.Problems = append(c.Problems, fmt.Sprintf("tx %s: %d of %d parties, need %d", id, n, m, opt.MinParties))
		}
		if minN < 0 || n < minN {
			minN = n
		}
		if n > maxN {
			maxN = n
		}
		if m > maxM {
			maxM = m
		}
	}
	// Withheld transactions (hashes-only export) carry no endorsements and are
	// not in prps. Say so, rather than letting "every transaction" cover them.
	withheld := map[string]bool{}
	for _, r := range p.Records {
		if t, has := p.Txs[r.Tx]; r.Tx != "" && has && t.Withheld {
			withheld[r.Tx] = true
		}
	}
	if len(ids) == 0 {
		if len(c.Problems) == 0 {
			c.Status = Warn
		}
		if len(withheld) > 0 {
			return finish(c, fmt.Sprintf("no transactions to check, %d withheld (no endorsements)", len(withheld)))
		}
		return finish(c, "no transactions to check")
	}
	names := make([]string, 0, len(used))
	for n := range used {
		names = append(names, n)
	}
	sort.Strings(names)
	scope := "transaction"
	if len(withheld) > 0 {
		scope = "endorsed transaction"
	}
	var detail string
	if minN == maxN {
		detail = fmt.Sprintf("%d of %d parties on every %s (%s)", minN, maxM, scope, strings.Join(names, ", "))
	} else {
		detail = fmt.Sprintf("%d to %d of %d parties per %s (%s)", minN, maxN, maxM, scope, strings.Join(names, ", "))
	}
	if len(withheld) > 0 {
		detail += fmt.Sprintf("; %d withheld (no endorsements)", len(withheld))
	}
	if pinned {
		detail += "; pinned"
	}
	return finish(c, detail)
}

func checkRedactions(p *pack.Pack) Check {
	c := Check{Name: NameRedactions}
	bySeq := map[int]bool{}
	for _, r := range p.Records {
		if r.Kind == "redaction" {
			bySeq[r.Seq] = false
		}
	}
	for id, err := range p.RedactionErr {
		c.Problems = append(c.Problems, fmt.Sprintf("redactions/%s.json unreadable: %v", id, err))
	}
	ids := make([]string, 0, len(p.Redactions))
	for id := range p.Redactions {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	hashOnly := 0
	for _, id := range ids {
		rd := p.Redactions[id]
		if _, ok := bySeq[rd.Seq]; !ok {
			c.Problems = append(c.Problems, fmt.Sprintf("redactions/%s.json names seq %d, which is not a redaction record", id, rd.Seq))
			continue
		}
		bySeq[rd.Seq] = true
		if rd.Content == nil {
			hashOnly++
			continue
		}
		content, err := base64.StdEncoding.DecodeString(*rd.Content)
		if err != nil {
			c.Problems = append(c.Problems, fmt.Sprintf("redactions/%s.json: content is not base64", id))
			continue
		}
		s := sha256.Sum256(content)
		if base64.StdEncoding.EncodeToString(s[:]) != rd.RedactedDataHash {
			c.Problems = append(c.Problems, fmt.Sprintf("redactions/%s.json: content does not match its stored hash", id))
		}
	}
	missing := []int{}
	for seq, seen := range bySeq {
		if !seen {
			missing = append(missing, seq)
		}
	}
	sort.Ints(missing)
	for _, seq := range missing {
		c.Problems = append(c.Problems, fmt.Sprintf("seq %d: redaction record has no redactions/ file", seq))
	}
	return finish(c, fmt.Sprintf("%d records, %d hashes-only", len(bySeq), hashOnly))
}

func summarise(p *pack.Pack) (Summary, []Refusal) {
	s := Summary{Records: len(p.Records)}
	refusals := []Refusal{}
	for _, r := range p.Records {
		switch r.Decision {
		case "allow":
			s.Allowed++
		case "narrow":
			s.Narrowed++
		case "refuse":
			s.Refused++
			refusals = append(refusals, Refusal{Seq: r.Seq, Time: r.Time, Agent: r.Agent, Action: r.Action, Reason: r.Reason})
		case "redact":
			s.Redacted++
		case "human":
			s.Human++
		case "revoke":
			s.Revoked++
		default:
			s.Recorded++
		}
	}
	return s, refusals
}
