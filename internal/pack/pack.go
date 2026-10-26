// Package pack reads a replay pack zip into memory and parses its files.
// Parsing problems in pack content are kept per file so the checks can report
// them; only an unreadable or unsafe container is an error here.
package pack

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
)

// Limits on what the reader accepts. A pack is evidence handed over by a
// third party, so the reader treats it as untrusted input.
const (
	MaxEntries    = 200000
	MaxTotalBytes = 512 << 20
	MaxEntryBytes = 256 << 20
)

type Root struct {
	SessionID   string `json:"sessionId"`
	InitiatorID string `json:"initiatorId"`
	OwnerID     string `json:"ownerId"`
}

type Exporter struct {
	MSPID   string `json:"mspId"`
	CertPEM string `json:"certPem"`
}

type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Signature struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

type Sources struct {
	Sessions string `json:"sessions"`
	Monitor  string `json:"monitor"`
}

type Manifest struct {
	PackVersion int         `json:"packVersion"`
	Tenant      string      `json:"tenant"`
	Scope       string      `json:"scope"`
	Root        Root        `json:"root"`
	ExportedAt  string      `json:"exportedAt"`
	Exporter    Exporter    `json:"exporter"`
	HashesOnly  bool        `json:"hashesOnly"`
	Sources     Sources     `json:"sources"`
	Files       []FileEntry `json:"files"`
	Signature   Signature   `json:"signature"`
}

type Record struct {
	Seq       int    `json:"seq"`
	Time      string `json:"time"`
	Kind      string `json:"kind"`
	Session   string `json:"session"`
	Agent     string `json:"agent"`
	Action    string `json:"action"`
	Decision  string `json:"decision"`
	Reason    string `json:"reason"`
	Channel   string `json:"channel"`
	Key       string `json:"key"`
	ValueHash string `json:"valueHash"`
	Tx        string `json:"tx"`
	PrevHash  string `json:"prevHash"`
	Hash      string `json:"hash"`

	// Raw is the line decoded with UseNumber; it carries unknown members,
	// which the hash covers.
	Raw map[string]any `json:"-"`
	// Line is the 1-based line number in records.jsonl.
	Line int `json:"-"`
}

type Endorsement struct {
	Endorser  string `json:"endorser"`
	Signature string `json:"signature"`
}

type Tx struct {
	TxID                    string        `json:"txId"`
	Channel                 string        `json:"channel"`
	BlockNumber             uint64        `json:"blockNumber"`
	Timestamp               string        `json:"timestamp"`
	ValidationCode          string        `json:"validationCode"`
	Function                string        `json:"function"`
	CreatorMSP              string        `json:"creatorMsp"`
	ProposalResponsePayload string        `json:"proposalResponsePayload,omitempty"`
	Endorsements            []Endorsement `json:"endorsements"`
	Withheld                bool          `json:"withheld"`
}

type Party struct {
	MSPID                string   `json:"mspId"`
	DisplayName          string   `json:"displayName"`
	Channels             []string `json:"channels"`
	RootCertsPEM         []string `json:"rootCertsPem"`
	IntermediateCertsPEM []string `json:"intermediateCertsPem"`
	Fingerprints         []string `json:"fingerprints"`
}

type Redaction struct {
	Seq                 int      `json:"seq"`
	RedactionID         string   `json:"redactionId"`
	Filters             []string `json:"filters"`
	RedactedDataHash    string   `json:"redactedDataHash"`
	OffchainStorageOnly bool     `json:"offchainStorageOnly"`
	Content             *string  `json:"content"`
}

// Pack is a fully loaded replay pack.
type Pack struct {
	Name  string
	Files map[string][]byte
	Order []string // zip entry order

	Manifest    *Manifest
	ManifestRaw map[string]any
	ManifestErr error

	Records    []Record
	RecordsErr error

	Parties    []Party
	PartiesErr error

	Txs   map[string]*Tx // by file name stem
	TxErr map[string]error

	Bodies map[int][]byte

	Redactions   map[string]*Redaction // by file name stem
	RedactionErr map[string]error
}

// Open reads and parses a pack from disk.
func Open(name string) (*Pack, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	p, err := Read(f, st.Size())
	if err != nil {
		return nil, err
	}
	p.Name = name
	return p, nil
}

// Read loads a pack from a zip.
func Read(r io.ReaderAt, size int64) (*Pack, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("not a readable zip: %w", err)
	}
	if len(zr.File) > MaxEntries {
		return nil, fmt.Errorf("too many entries (%d > %d)", len(zr.File), MaxEntries)
	}
	p := &Pack{Files: map[string][]byte{}}
	var total int64
	for _, zf := range zr.File {
		if err := safeName(zf.Name); err != nil {
			return nil, err
		}
		if zf.FileInfo().IsDir() {
			continue
		}
		if !zf.Mode().IsRegular() {
			return nil, fmt.Errorf("entry %q is not a regular file", zf.Name)
		}
		if _, dup := p.Files[zf.Name]; dup {
			return nil, fmt.Errorf("duplicate entry %q", zf.Name)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", zf.Name, err)
		}
		b, err := io.ReadAll(io.LimitReader(rc, MaxEntryBytes+1))
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", zf.Name, err)
		}
		if len(b) > MaxEntryBytes {
			return nil, fmt.Errorf("entry %q larger than %d bytes", zf.Name, MaxEntryBytes)
		}
		total += int64(len(b))
		if total > MaxTotalBytes {
			return nil, fmt.Errorf("pack larger than %d bytes uncompressed", MaxTotalBytes)
		}
		p.Files[zf.Name] = b
		p.Order = append(p.Order, zf.Name)
	}
	p.parse()
	return p, nil
}

func safeName(n string) error {
	if n == "" || strings.HasPrefix(n, "/") || strings.Contains(n, "\\") {
		return fmt.Errorf("unsafe entry name %q", n)
	}
	for _, seg := range strings.Split(n, "/") {
		if seg == ".." {
			return fmt.Errorf("unsafe entry name %q", n)
		}
	}
	if path.Clean(n) != strings.TrimSuffix(n, "/") {
		return fmt.Errorf("unsafe entry name %q", n)
	}
	return nil
}

func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(v)
}

func (p *Pack) parse() {
	if b, ok := p.Files["manifest.json"]; !ok {
		p.ManifestErr = fmt.Errorf("manifest.json missing")
	} else {
		var m Manifest
		if err := json.Unmarshal(b, &m); err != nil {
			p.ManifestErr = fmt.Errorf("manifest.json: %w", err)
		} else if err := decodeStrict(b, &p.ManifestRaw); err != nil {
			p.ManifestErr = fmt.Errorf("manifest.json: %w", err)
		} else {
			p.Manifest = &m
		}
	}

	if b, ok := p.Files["records.jsonl"]; !ok {
		p.RecordsErr = fmt.Errorf("records.jsonl missing")
	} else {
		p.Records, p.RecordsErr = ParseRecords(b)
	}

	if b, ok := p.Files["parties.json"]; !ok {
		p.PartiesErr = fmt.Errorf("parties.json missing")
	} else if err := json.Unmarshal(b, &p.Parties); err != nil {
		p.PartiesErr = fmt.Errorf("parties.json: %w", err)
	}

	p.Txs, p.TxErr = map[string]*Tx{}, map[string]error{}
	p.Bodies = map[int][]byte{}
	p.Redactions, p.RedactionErr = map[string]*Redaction{}, map[string]error{}
	names := make([]string, 0, len(p.Files))
	for n := range p.Files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		b := p.Files[n]
		switch {
		case strings.HasPrefix(n, "tx/") && strings.HasSuffix(n, ".json"):
			id := strings.TrimSuffix(strings.TrimPrefix(n, "tx/"), ".json")
			var t Tx
			if err := json.Unmarshal(b, &t); err != nil {
				p.TxErr[id] = err
			} else {
				p.Txs[id] = &t
			}
		case strings.HasPrefix(n, "bodies/") && strings.HasSuffix(n, ".json"):
			s := strings.TrimSuffix(strings.TrimPrefix(n, "bodies/"), ".json")
			if seq, err := strconv.Atoi(s); err == nil {
				p.Bodies[seq] = b
			}
		case strings.HasPrefix(n, "redactions/") && strings.HasSuffix(n, ".json"):
			id := strings.TrimSuffix(strings.TrimPrefix(n, "redactions/"), ".json")
			var r Redaction
			if err := json.Unmarshal(b, &r); err != nil {
				p.RedactionErr[id] = err
			} else {
				p.Redactions[id] = &r
			}
		}
	}
}

// ParseRecords parses records.jsonl. A line that does not parse is an error:
// the chain cannot be checked past it.
func ParseRecords(b []byte) ([]Record, error) {
	if len(b) == 0 {
		return nil, nil
	}
	if b[len(b)-1] != '\n' {
		return nil, fmt.Errorf("records.jsonl: last line not terminated by \\n")
	}
	lines := bytes.Split(b[:len(b)-1], []byte("\n"))
	out := make([]Record, 0, len(lines))
	for i, ln := range lines {
		if len(bytes.TrimSpace(ln)) == 0 {
			return nil, fmt.Errorf("records.jsonl line %d: blank line", i+1)
		}
		var r Record
		if err := json.Unmarshal(ln, &r); err != nil {
			return nil, fmt.Errorf("records.jsonl line %d: %w", i+1, err)
		}
		if err := decodeStrict(ln, &r.Raw); err != nil {
			return nil, fmt.Errorf("records.jsonl line %d: %w", i+1, err)
		}
		r.Line = i + 1
		out = append(out, r)
	}
	return out, nil
}
