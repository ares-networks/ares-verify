package replaypack_test

import (
	"fmt"
	"time"

	"github.com/ares-networks/ares-verify/pkg/replaypack"
)

// Build a one-record pack signed by a throwaway organisation. Write the zip
// to a file and check it with ares-verify.
func ExampleBuild() {
	now := time.Now().UTC()
	id, err := replaypack.NewEphemeralIdentity("DemoMSP", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		panic(err)
	}
	p, err := replaypack.Build(replaypack.Spec{
		Tenant: "example-tenant", Scope: "job",
		Root:     replaypack.Root{SessionID: "sess-1", InitiatorID: "agent-a", OwnerID: "agent-a"},
		Parties:  []replaypack.PartySpec{{Identity: id, DisplayName: "Demo organisation"}},
		Exporter: id, ExportedAt: now,
		Entries: []replaypack.Entry{{Time: now, Kind: "session-open", Session: "sess-1", Agent: "agent-a",
			Decision: "allow", Channel: "sessions", Chaincode: "sessions-cc",
			Key: replaypack.CompositeKey("session", "sess-1"), Value: []byte(`{"state":"open"}`)}},
	})
	if err != nil {
		panic(err)
	}
	zip, err := p.Zip()
	if err != nil {
		panic(err)
	}
	fmt.Println(len(p.Files), "files,", len(zip) > 0)
	// Output: 6 files, true
}
