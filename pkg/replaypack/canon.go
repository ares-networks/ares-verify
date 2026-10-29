package replaypack

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"

	"github.com/ares-networks/ares-verify/internal/canon"
)

// GenesisHash is the prevHash of record 1 (64 zeros).
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// RecordHash returns hex SHA-256( JCS(record without "hash") || prevHash ),
// FORMAT.md §4. prevHash is taken from the record itself. Numbers must be
// integers (use json.Number or Go integer types).
func RecordHash(raw map[string]any) (string, error) {
	m := make(map[string]any, len(raw))
	for k, v := range raw {
		if k != "hash" {
			m[k] = v
		}
	}
	prev, _ := raw["prevHash"].(string)
	b, err := canon.Encode(m)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(b)
	h.Write([]byte(prev))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Fingerprint is hex SHA-256 of a certificate's DER: the value --pin takes.
func Fingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}
