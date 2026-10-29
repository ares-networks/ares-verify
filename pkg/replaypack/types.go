package replaypack

// Wire types of FORMAT.md v1. Field names and JSON tags are the format.

// Root is manifest.root: the session tree the pack covers.
type Root struct {
	SessionID   string `json:"sessionId"`
	InitiatorID string `json:"initiatorId"`
	OwnerID     string `json:"ownerId"`
}

// Exporter is manifest.exporter.
type Exporter struct {
	MSPID   string `json:"mspId"`
	CertPEM string `json:"certPem"`
}

// FileEntry is one manifest.files item.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Signature is manifest.signature.
type Signature struct {
	Alg   string `json:"alg"`
	Value string `json:"value"`
}

// Sources is manifest.sources: "ledger", "index" or "not-configured".
type Sources struct {
	Sessions string `json:"sessions"`
	Monitor  string `json:"monitor"`
}

// Manifest is manifest.json.
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

// Endorsement is one tx endorsement: base64 SerializedIdentity and DER
// signature.
type Endorsement struct {
	Endorser  string `json:"endorser"`
	Signature string `json:"signature"`
}

// Tx is tx/<txId>.json.
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

// Party is one parties.json item.
type Party struct {
	MSPID                string   `json:"mspId"`
	DisplayName          string   `json:"displayName"`
	Channels             []string `json:"channels"`
	RootCertsPEM         []string `json:"rootCertsPem"`
	IntermediateCertsPEM []string `json:"intermediateCertsPem"`
	Fingerprints         []string `json:"fingerprints"`
}

// Redaction is redactions/<id>.json.
type Redaction struct {
	Seq                 int      `json:"seq"`
	RedactionID         string   `json:"redactionId"`
	Filters             []string `json:"filters"`
	RedactedDataHash    string   `json:"redactedDataHash"`
	OffchainStorageOnly bool     `json:"offchainStorageOnly"`
	Content             *string  `json:"content"`
}
