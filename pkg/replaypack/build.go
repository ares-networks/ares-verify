package replaypack

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ares-networks/ares-verify/internal/canon"
)

// PartySpec is one organisation in parties.json.
type PartySpec struct {
	Identity    *Identity
	DisplayName string   // "" = the MSP id
	Channels    []string // nil = every channel in the pack
}

// RedactionSpec is the redaction behind an entry of kind "redaction".
type RedactionSpec struct {
	ID      string
	Filters []string
	// Content is the stripped bytes. redactedDataHash is base64 std of its
	// SHA-256, and redactions/<id>.json carries it unless the pack is
	// hashes-only.
	Content []byte
	// OffchainOnly: the ledger value keeps the hash only (offchainStorageOnly).
	OffchainOnly bool
	// SenderID and ReceiverID go into the ledger value Build writes when
	// Entry.Value is nil. SenderID "" = Entry.Agent.
	SenderID, ReceiverID string
}

// Entry is one record and the transaction that wrote it.
type Entry struct {
	Time     time.Time
	Kind     string // FORMAT.md §4 kinds
	Session  string
	Agent    string
	Action   string
	Decision string
	Reason   string

	Channel   string
	Chaincode string // namespace of the write
	Key       string
	// Value is the exact ledger value. With Redaction set and Value nil, Build
	// writes a redaction record value holding RedactionSpec; with Value set,
	// Value is used as is and must be what the ledger stored.
	Value  []byte
	Delete bool

	TxID        string // "" = hex SHA-256 of "<tenant>/<seq>"
	BlockNumber uint64 // 0 = seq
	Function    string // label only
	CreatorMSP  string // "" = the exporter's MSP id
	// Endorsers: nil = every party; an empty non-nil slice = none.
	Endorsers []*Identity
	Redaction *RedactionSpec
	NoBody    bool // leave bodies/<seq>.json out
}

// Spec describes a pack to build.
type Spec struct {
	Tenant     string
	Scope      string // "job" or "session-tree"
	Root       Root
	Parties    []PartySpec
	Exporter   *Identity // must be one of Parties
	HashesOnly bool
	ExportedAt time.Time
	Sources    Sources // zero = ledger, ledger
	Entries    []Entry
	Readme     string // "" = DefaultReadme
}

// Pack is a built pack as a set of files, keyed by zip entry name.
type Pack struct {
	Files    map[string][]byte
	Exporter *Identity
}

// DefaultReadme is README.txt when Spec.Readme is empty.
const DefaultReadme = `This is a replay pack: a signed export of what was recorded for one job.

Check it with ares-verify (open source):

    ares-verify <this file>.zip

A PASS means the records were not edited, removed or reordered after export,
each record matches the ledger write it points at, and the listed
organisations endorsed those writes with their own keys.

A PASS does not mean the agents' outputs were correct, that nothing happened
outside the recording path, or that the pack holds every record that exists.
`

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func (s *Spec) validate() error {
	if s.Exporter == nil {
		return errors.New("no exporter")
	}
	if len(s.Parties) == 0 {
		return errors.New("no parties")
	}
	seen := map[string]bool{}
	exporterListed := false
	for i, p := range s.Parties {
		if p.Identity == nil {
			return fmt.Errorf("party %d: no identity", i+1)
		}
		if seen[p.Identity.MSPID] {
			return fmt.Errorf("party %s listed twice", p.Identity.MSPID)
		}
		seen[p.Identity.MSPID] = true
		if p.Identity.MSPID == s.Exporter.MSPID {
			exporterListed = true
		}
	}
	if !exporterListed {
		return fmt.Errorf("exporter %s is not a party", s.Exporter.MSPID)
	}
	var prev time.Time
	for i, e := range s.Entries {
		seq := i + 1
		switch {
		case e.Kind == "":
			return fmt.Errorf("entry %d: no kind", seq)
		case e.Channel == "" || e.Chaincode == "" || e.Key == "":
			return fmt.Errorf("entry %d: channel, chaincode and key are required", seq)
		case e.Time.Before(prev):
			return fmt.Errorf("entry %d: time before the previous entry", seq)
		case e.Redaction != nil && e.Redaction.ID == "":
			return fmt.Errorf("entry %d: redaction without id", seq)
		case e.Redaction != nil && e.Delete:
			return fmt.Errorf("entry %d: redaction cannot be a delete", seq)
		}
		prev = e.Time
	}
	return nil
}

// Build lays out every file and signs the manifest with the exporter's key.
func Build(s Spec) (*Pack, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	p := &Pack{Files: map[string][]byte{}, Exporter: s.Exporter}
	channels := map[string]bool{}
	txSeen := map[string]bool{}
	redSeen := map[string]bool{}
	var lines []map[string]any
	for i := range s.Entries {
		e := s.Entries[i] // copy: defaults never write back to the caller's slice
		seq := i + 1
		channels[e.Channel] = true
		if e.TxID == "" {
			h := sha256.Sum256([]byte(fmt.Sprintf("%s/%d", s.Tenant, seq)))
			e.TxID = hex.EncodeToString(h[:])
		}
		if txSeen[e.TxID] {
			return nil, fmt.Errorf("entry %d: transaction %s already used", seq, e.TxID)
		}
		txSeen[e.TxID] = true
		if e.BlockNumber == 0 {
			e.BlockNumber = uint64(seq)
		}
		if e.CreatorMSP == "" {
			e.CreatorMSP = s.Exporter.MSPID
		}
		value := e.Value
		var redFile *Redaction
		if e.Redaction != nil {
			if redSeen[e.Redaction.ID] {
				return nil, fmt.Errorf("entry %d: redaction %s already used", seq, e.Redaction.ID)
			}
			redSeen[e.Redaction.ID] = true
			v, rf, err := redactionValue(&e, seq, s.HashesOnly)
			if err != nil {
				return nil, fmt.Errorf("entry %d: %w", seq, err)
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

		tx := Tx{TxID: e.TxID, Channel: e.Channel, BlockNumber: e.BlockNumber,
			Timestamp: rfc3339(e.Time), ValidationCode: "VALID",
			Function: e.Function, CreatorMSP: e.CreatorMSP,
			Endorsements: []Endorsement{}, Withheld: withheld}
		if !withheld {
			prp, err := BuildPRP(e.Chaincode, e.TxID, []KVWrite{{Key: e.Key, Value: value, IsDelete: e.Delete}})
			if err != nil {
				return nil, err
			}
			tx.ProposalResponsePayload = base64.StdEncoding.EncodeToString(prp)
			endorsers := e.Endorsers
			if endorsers == nil {
				for _, ps := range s.Parties {
					endorsers = append(endorsers, ps.Identity)
				}
			}
			for _, o := range endorsers {
				eb, sig, err := o.Endorse(prp)
				if err != nil {
					return nil, err
				}
				tx.Endorsements = append(tx.Endorsements, Endorsement{
					Endorser:  base64.StdEncoding.EncodeToString(eb),
					Signature: base64.StdEncoding.EncodeToString(sig)})
			}
		}
		txb, err := json.MarshalIndent(tx, "", "  ")
		if err != nil {
			return nil, err
		}
		p.Files["tx/"+e.TxID+".json"] = txb

		if !e.NoBody && !e.Delete && !(s.HashesOnly && e.Redaction != nil) {
			p.Files[fmt.Sprintf("bodies/%d.json", seq)] = value
		}
		if redFile != nil {
			rb, err := json.MarshalIndent(redFile, "", "  ")
			if err != nil {
				return nil, err
			}
			p.Files["redactions/"+e.Redaction.ID+".json"] = rb
		}
		lines = append(lines, map[string]any{
			"seq": json.Number(fmt.Sprint(seq)), "time": rfc3339(e.Time),
			"kind": e.Kind, "session": e.Session, "agent": e.Agent, "action": e.Action,
			"decision": e.Decision, "reason": e.Reason, "channel": e.Channel, "key": e.Key,
			"valueHash": valueHash, "tx": e.TxID,
		})
	}
	if err := p.WriteRecords(lines, true); err != nil {
		return nil, err
	}

	all := make([]string, 0, len(channels))
	for c := range channels {
		all = append(all, c)
	}
	sort.Strings(all)
	ps := make([]Party, 0, len(s.Parties))
	for _, sp := range s.Parties {
		id := sp.Identity
		chs := all
		if sp.Channels != nil {
			chs = append([]string{}, sp.Channels...)
			sort.Strings(chs)
		}
		name := sp.DisplayName
		if name == "" {
			name = id.MSPID
		}
		fps := make([]string, 0, len(id.Roots))
		for _, r := range id.Roots {
			fps = append(fps, Fingerprint(r))
		}
		ps = append(ps, Party{MSPID: id.MSPID, DisplayName: name, Channels: chs,
			RootCertsPEM: append([]string{}, id.RootsPEM...), IntermediateCertsPEM: []string{},
			Fingerprints: fps})
	}
	pb, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return nil, err
	}
	p.Files["parties.json"] = pb
	readme := s.Readme
	if readme == "" {
		readme = DefaultReadme
	}
	p.Files["README.txt"] = []byte(readme)

	src := s.Sources
	if src == (Sources{}) {
		src = Sources{Sessions: "ledger", Monitor: "ledger"}
	}
	m := Manifest{PackVersion: 1, Tenant: s.Tenant, Scope: s.Scope, Root: s.Root,
		ExportedAt: rfc3339(s.ExportedAt),
		Exporter:   Exporter{MSPID: s.Exporter.MSPID, CertPEM: s.Exporter.CertPEM},
		HashesOnly: s.HashesOnly, Sources: src}
	mb, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	p.Files["manifest.json"] = mb
	return p, p.Resign()
}

// redactionValue returns the ledger value of a redaction entry and its
// redactions/ file.
func redactionValue(e *Entry, seq int, hashesOnly bool) ([]byte, *Redaction, error) {
	r := e.Redaction
	sum := sha256.Sum256(r.Content)
	hash := base64.StdEncoding.EncodeToString(sum[:])
	filters := r.Filters
	if filters == nil {
		filters = []string{}
	}
	value := e.Value
	if value == nil {
		sender := r.SenderID
		if sender == "" {
			sender = e.Agent
		}
		ledger := map[string]any{
			"id": r.ID, "senderId": sender, "receiverId": r.ReceiverID, "credSessionId": e.Session,
			"utc": e.Time.Unix(), "redactionFilters": filters, "redactedDataHash": hash,
		}
		if !r.OffchainOnly {
			ledger["redactedDataJson"] = json.RawMessage(r.Content)
		}
		v, err := json.Marshal(ledger)
		if err != nil {
			return nil, nil, fmt.Errorf("redaction %s: %w", r.ID, err)
		}
		value = v
	}
	rf := &Redaction{Seq: seq, RedactionID: r.ID, Filters: filters, RedactedDataHash: hash,
		OffchainStorageOnly: r.OffchainOnly}
	if !hashesOnly {
		c := base64.StdEncoding.EncodeToString(r.Content)
		rf.Content = &c
	}
	return value, rf, nil
}

// WriteRecords writes records.jsonl. With rechain, prevHash and hash are
// recomputed (what an exporter does); without, lines are written as given.
// Numbers in lines must be integers (json.Number or Go integer types).
func (p *Pack) WriteRecords(lines []map[string]any, rechain bool) error {
	var buf bytes.Buffer
	prev := GenesisHash
	for _, l := range lines {
		if rechain {
			l["prevHash"] = prev
			delete(l, "hash")
			h, err := RecordHash(l)
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

// Records returns records.jsonl as maps decoded with json.Number, ready to
// change and pass back to WriteRecords.
func (p *Pack) Records() ([]map[string]any, error) {
	b := p.Files["records.jsonl"]
	if len(b) == 0 {
		return nil, nil
	}
	var out []map[string]any
	for i, ln := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		dec := json.NewDecoder(strings.NewReader(ln))
		dec.UseNumber()
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			return nil, fmt.Errorf("records.jsonl line %d: %w", i+1, err)
		}
		out = append(out, m)
	}
	return out, nil
}

// Resign recomputes manifest.files and the exporter signature over
// JCS(manifest without signature), as an exporter holding the key would.
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
	sig, err := p.Exporter.Sign(d[:])
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

// Zip writes the pack: manifest.json first, then every other file in name
// order, deflated, all with the same fixed modification time, so equal files
// give an equal zip.
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
