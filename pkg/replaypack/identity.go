package replaypack

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"google.golang.org/protobuf/proto"
)

// CA is a self-signed P-256 root that can issue signing certificates.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM string
}

// Identity is one organisation's signing identity: a certificate, its key,
// and the roots it chains to. It endorses transactions and, as the exporter,
// signs the manifest. Roots go to parties.json as the organisation's
// rootCertsPem.
type Identity struct {
	MSPID    string
	Cert     *x509.Certificate
	CertPEM  string
	Key      *ecdsa.PrivateKey
	Roots    []*x509.Certificate
	RootsPEM []string
}

func pemCert(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// NewCA creates a self-signed P-256 root CA valid from nb to na.
func NewCA(cn, org string, nb, na time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:             nb,
		NotAfter:              na,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key, CertPEM: pemCert(der)}, nil
}

// Issue creates a P-256 signing certificate under c: digital signature only,
// no SANs. It returns the certificate PEM and the key as PKCS #8 PEM.
func (c *CA) Issue(cn, org string, nb, na time.Time) (certPEM, keyPEM string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	sn, err := serial()
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{org}},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		return "", "", err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	return pemCert(der), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})), nil
}

// Fingerprint is the CA certificate's fingerprint (hex SHA-256 of its DER).
func (c *CA) Fingerprint() string { return Fingerprint(c.Cert) }

func parseCerts(s string) ([]*x509.Certificate, error) {
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
		return nil, errors.New("no certificate in PEM")
	}
	return out, nil
}

func parseKey(s string) (*ecdsa.PrivateKey, error) {
	rest := []byte(s)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return nil, errors.New("no private key in PEM")
		}
		switch blk.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			ek, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is %T, want ECDSA", k)
			}
			return ek, nil
		}
	}
}

// NewIdentity loads a signing identity from PEM: the certificate, its ECDSA
// P-256 key (SEC 1 "EC PRIVATE KEY" or PKCS #8 "PRIVATE KEY"), and one or more
// root CA certificates (each argument may hold several). The key must match
// the certificate, and the certificate must chain directly to one of the
// roots at its own NotBefore. Intermediates are not supported.
func NewIdentity(mspID, certPEM, keyPEM string, rootPEMs ...string) (*Identity, error) {
	if mspID == "" {
		return nil, errors.New("empty MSP id")
	}
	certs, err := parseCerts(certPEM)
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	cert := certs[0]
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("key: curve is not P-256")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		return nil, errors.New("key does not match certificate")
	}
	if len(rootPEMs) == 0 {
		return nil, errors.New("no root certificate")
	}
	id := &Identity{MSPID: mspID, Cert: cert, CertPEM: pemCert(cert.Raw), Key: key}
	pool := x509.NewCertPool()
	for i, r := range rootPEMs {
		cs, err := parseCerts(r)
		if err != nil {
			return nil, fmt.Errorf("root %d: %w", i+1, err)
		}
		for _, c := range cs {
			if !c.IsCA || !c.BasicConstraintsValid {
				return nil, fmt.Errorf("root %d: certificate %q is not a CA", i+1, c.Subject.CommonName)
			}
			pool.AddCert(c)
			id.Roots = append(id.Roots, c)
			id.RootsPEM = append(id.RootsPEM, pemCert(c.Raw))
		}
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: cert.NotBefore,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("certificate does not chain to the given roots: %w", err)
	}
	return id, nil
}

// NewEphemeralIdentity creates a fresh root and a signing identity under it,
// both valid from nb to na and held only in memory. Every call yields a
// different root, so its packs cannot be pinned in advance.
func NewEphemeralIdentity(mspID string, nb, na time.Time) (*Identity, error) {
	ca, err := NewCA(mspID+" ephemeral root", mspID, nb, na)
	if err != nil {
		return nil, err
	}
	cert, key, err := ca.Issue(mspID+" ephemeral signer", mspID, nb, na)
	if err != nil {
		return nil, err
	}
	return NewIdentity(mspID, cert, key, ca.CertPEM)
}

// SerializedIdentity is the msp.SerializedIdentity bytes of the certificate.
func (id *Identity) SerializedIdentity() []byte {
	b, _ := proto.Marshal(&msp.SerializedIdentity{Mspid: id.MSPID, IdBytes: []byte(id.CertPEM)})
	return b
}

// Endorse signs SHA-256(prp || SerializedIdentity), DER, low-S, as a ledger
// endorser does. It returns the endorser bytes and the signature.
func (id *Identity) Endorse(prp []byte) (endorser, sig []byte, err error) {
	endorser = id.SerializedIdentity()
	d := sha256.Sum256(append(append([]byte{}, prp...), endorser...))
	sig, err = SignLowS(id.Key, d[:])
	return endorser, sig, err
}

// Sign signs a digest, DER, low-S.
func (id *Identity) Sign(digest []byte) ([]byte, error) { return SignLowS(id.Key, digest) }

// SignLowS returns an ASN.1 DER ECDSA signature with S in the lower half.
func SignLowS(k *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig, &rs); err != nil {
		return nil, err
	}
	n := k.Curve.Params().N
	if rs.S.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		rs.S.Sub(n, rs.S)
	}
	return asn1.Marshal(rs)
}
