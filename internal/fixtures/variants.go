package fixtures

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ares-networks/ares-verify/internal/pack"
)

// DefaultSpec is a two-organisation job: a session opened, narrowed, two
// redactions (one hash-only on the ledger), one refusal, and an expiry.
func DefaultSpec() (Spec, error) {
	org1, err := NewOrg("Org1MSP")
	if err != nil {
		return Spec{}, err
	}
	org2, err := NewOrg("Org2MSP")
	if err != nil {
		return Spec{}, err
	}
	t0 := time.Date(2026, 10, 14, 9, 2, 0, 0, time.UTC)
	at := func(min int) time.Time { return t0.Add(time.Duration(min) * time.Minute) }
	const sess, ch, mon = "sess-0001", "sessions", "monitor"
	const sessCC, monCC = "sessions-cc", "monitor-cc"
	sessKey := CompositeKey("cred-session", "agent-a", "owner-1", sess)
	body := func(state string) []byte {
		b, _ := json.Marshal(map[string]any{"sessionId": sess, "state": state, "scopes": []string{"orders.read"}})
		return b
	}
	entries := []Entry{
		{Time: at(0), Kind: "session-open", Session: sess, Agent: "agent-a", Decision: "record", Reason: "session opened", Channel: ch, Chain: sessCC, Key: sessKey, Value: body("open")},
		{Time: at(1), Kind: "filters", Session: sess, Agent: "agent-a", Decision: "record", Channel: ch, Chain: sessCC, Key: sessKey, Value: body("filters")},
		{Time: at(2), Kind: "intersect", Session: sess, Agent: "agent-b", Action: "orders.read", Decision: "narrow", Reason: "badge narrowed to 1 scope", Channel: ch, Chain: sessCC, Key: sessKey, Value: body("intersected")},
		{Time: at(5), Kind: "redaction", Session: sess, Agent: "agent-b", Action: "filter-pii", Decision: "redact", Reason: "personal data", Channel: mon, Chain: monCC,
			Key:       CompositeKey("aresredaction", "agent-b", "receiver", "red-0001"),
			Redaction: &RedactionEntry{ID: "red-0001", Filters: []string{"filter-pii"}, Content: []byte(`[{"kind":"text","text":"a@b.example"}]`)}},
		{Time: at(9), Kind: "guard-exception", Session: sess, Agent: "agent-b", Action: "send-external", Decision: "refuse", Reason: "outside badge", Channel: mon, Chain: monCC,
			Key: CompositeKey("aresguardexception", "agent-b", "receiver", "exc-0001"), Value: []byte(`{"exceptionId":"exc-0001","violationType":"scope","detail":"outside badge"}`)},
		{Time: at(12), Kind: "redaction", Session: sess, Agent: "agent-b", Action: "filter-prices", Decision: "redact", Reason: "commercial terms", Channel: mon, Chain: monCC,
			Key:       CompositeKey("aresredaction", "agent-b", "receiver", "red-0002"),
			Redaction: &RedactionEntry{ID: "red-0002", Filters: []string{"filter-prices"}, Content: []byte(`[{"kind":"text","text":"unit price 4.20"}]`), OffchainOnly: true}},
		{Time: at(39), Kind: "expire", Session: sess, Agent: "agent-a", Decision: "revoke", Reason: "job finished", Channel: ch, Chain: sessCC, Key: sessKey, Value: body("expired")},
	}
	return Spec{
		Tenant: "example-tenant", Scope: "job",
		Root: pack.Root{SessionID: sess, InitiatorID: "agent-a", OwnerID: "owner-1"},
		Orgs: []*Org{org1, org2}, Exporter: org1, ExportedAt: at(40), Entries: entries,
	}, nil
}

// Variant names, in the order gen-fixtures writes them.
var Variants = []string{"valid", "tampered-record", "dropped-record", "missing-endorsement", "swapped-party-cert", "hashes-only"}

// BuildVariant builds one named fixture.
func BuildVariant(name string) (*Pack, error) {
	s, err := DefaultSpec()
	if err != nil {
		return nil, err
	}
	switch name {
	case "valid":
		return Build(s)
	case "hashes-only":
		s.HashesOnly = true
		return Build(s)
	case "missing-endorsement":
		s.Entries[2].Endorsers = []*Org{}
		return Build(s)
	case "tampered-record":
		// Insider edit: change a reason, re-sign the manifest, keep the chain.
		p, err := Build(s)
		if err != nil {
			return nil, err
		}
		recs, err := p.Records()
		if err != nil {
			return nil, err
		}
		recs[4]["reason"] = "within badge"
		if err := p.WriteRecords(recs, false); err != nil {
			return nil, err
		}
		return p, p.Resign()
	case "dropped-record":
		p, err := Build(s)
		if err != nil {
			return nil, err
		}
		recs, err := p.Records()
		if err != nil {
			return nil, err
		}
		recs = append(recs[:4], recs[5:]...)
		if err := p.WriteRecords(recs, false); err != nil {
			return nil, err
		}
		return p, p.Resign()
	case "swapped-party-cert":
		// Replace the exporter's party root with an unrelated CA.
		p, err := Build(s)
		if err != nil {
			return nil, err
		}
		other, err := NewOrg(s.Exporter.MSPID)
		if err != nil {
			return nil, err
		}
		var ps []pack.Party
		if err := json.Unmarshal(p.Files["parties.json"], &ps); err != nil {
			return nil, err
		}
		for i := range ps {
			if ps[i].MSPID == s.Exporter.MSPID {
				ps[i].RootCertsPEM = []string{other.CAPEM}
				ps[i].Fingerprints = nil
			}
		}
		pb, _ := json.MarshalIndent(ps, "", "  ")
		p.Files["parties.json"] = pb
		return p, p.Resign()
	}
	names := append([]string{}, Variants...)
	sort.Strings(names)
	return nil, fmt.Errorf("unknown variant %q (have %v)", name, names)
}
