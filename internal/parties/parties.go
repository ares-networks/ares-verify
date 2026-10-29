// Package parties turns parties.json into per-organisation trust roots.
package parties

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ares-networks/ares-verify/internal/pack"
	"github.com/ares-networks/ares-verify/pkg/replaypack"
)

// Party is one organisation with parsed certificates.
type Party struct {
	MSPID        string
	DisplayName  string
	Channels     map[string]bool
	Roots        *x509.CertPool
	Inters       *x509.CertPool
	Fingerprints []string // computed from the root DER, not trusted from the file
	Pinned       bool
}

// Set is every party in a pack.
type Set struct {
	ByMSP map[string]*Party
	Order []string
}

// Fingerprint is hex SHA-256 of a certificate's DER.
func Fingerprint(c *x509.Certificate) string { return replaypack.Fingerprint(c) }

func parsePEM(s string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(s)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificate in PEM")
	}
	return out, nil
}

// ParseCert parses the first certificate in a PEM string.
func ParseCert(s string) (*x509.Certificate, error) {
	cs, err := parsePEM(s)
	if err != nil {
		return nil, err
	}
	return cs[0], nil
}

// Build parses parties and applies pins (hex fingerprints, any case, with or
// without colons). Problems are returned as lines; a broken party is dropped.
func Build(ps []pack.Party, pins []string) (*Set, []string) {
	pinset := map[string]bool{}
	for _, p := range pins {
		p = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), ":", ""))
		if p != "" {
			pinset[p] = true
		}
	}
	set := &Set{ByMSP: map[string]*Party{}}
	var problems []string
	for _, p := range ps {
		if p.MSPID == "" {
			problems = append(problems, "party with empty mspId")
			continue
		}
		if _, dup := set.ByMSP[p.MSPID]; dup {
			problems = append(problems, fmt.Sprintf("party %s listed twice", p.MSPID))
			continue
		}
		pt := &Party{MSPID: p.MSPID, DisplayName: p.DisplayName, Channels: map[string]bool{},
			Roots: x509.NewCertPool(), Inters: x509.NewCertPool()}
		for _, ch := range p.Channels {
			pt.Channels[ch] = true
		}
		ok := true
		for _, r := range p.RootCertsPEM {
			cs, err := parsePEM(r)
			if err != nil {
				problems = append(problems, fmt.Sprintf("party %s: bad root certificate: %v", p.MSPID, err))
				ok = false
				break
			}
			for _, c := range cs {
				pt.Roots.AddCert(c)
				fp := Fingerprint(c)
				pt.Fingerprints = append(pt.Fingerprints, fp)
				if pinset[fp] {
					pt.Pinned = true
				}
			}
		}
		for _, r := range p.IntermediateCertsPEM {
			cs, err := parsePEM(r)
			if err != nil {
				problems = append(problems, fmt.Sprintf("party %s: bad intermediate certificate: %v", p.MSPID, err))
				ok = false
				break
			}
			for _, c := range cs {
				pt.Inters.AddCert(c)
			}
		}
		if !ok || len(pt.Fingerprints) == 0 {
			if ok {
				problems = append(problems, fmt.Sprintf("party %s has no root certificate", p.MSPID))
			}
			continue
		}
		if len(p.Fingerprints) > 0 && strings.Join(p.Fingerprints, ",") != strings.Join(pt.Fingerprints, ",") {
			problems = append(problems, fmt.Sprintf("party %s: listed fingerprints do not match its root certificates", p.MSPID))
		}
		set.ByMSP[p.MSPID] = pt
		set.Order = append(set.Order, p.MSPID)
	}
	return set, problems
}

// OnChannel counts parties that list a channel (M).
func (s *Set) OnChannel(ch string) int {
	n := 0
	for _, p := range s.ByMSP {
		if p.Channels[ch] {
			n++
		}
	}
	return n
}

// VerifyChain checks that cert chains to the roots of party msp at time at.
func (s *Set) VerifyChain(mspID string, cert *x509.Certificate, at time.Time) error {
	p, ok := s.ByMSP[mspID]
	if !ok {
		return fmt.Errorf("unknown party %s", mspID)
	}
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:         p.Roots,
		Intermediates: p.Inters,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	var invalid x509.CertificateInvalidError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &invalid):
		return fmt.Errorf("certificate does not chain to %s: %s", mspID, invalid.Error())
	default:
		return fmt.Errorf("certificate does not chain to %s (not issued by its root)", mspID)
	}
}
