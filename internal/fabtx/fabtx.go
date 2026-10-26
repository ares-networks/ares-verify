// Package fabtx decodes the endorsed part of a ledger transaction and checks
// endorsement signatures (FORMAT.md §5).
package fabtx

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
)

// Write is one key written by the chaincode.
type Write struct {
	Key      string
	Value    []byte
	IsDelete bool
}

// Action is what the endorsers signed, decoded.
type Action struct {
	Chaincode string
	Version   string
	Writes    []Write // the chaincode's own namespace only
}

// DecodePRP decodes ProposalResponsePayload -> ChaincodeAction -> rwset, and
// returns the writes in the chaincode's own namespace.
func DecodePRP(prpBytes []byte) (*Action, error) {
	var prp peer.ProposalResponsePayload
	if err := proto.Unmarshal(prpBytes, &prp); err != nil {
		return nil, fmt.Errorf("proposal response payload: %w", err)
	}
	var ca peer.ChaincodeAction
	if err := proto.Unmarshal(prp.GetExtension(), &ca); err != nil {
		return nil, fmt.Errorf("chaincode action: %w", err)
	}
	if ca.GetChaincodeId().GetName() == "" {
		return nil, errors.New("chaincode action has no chaincode id")
	}
	var txrw rwset.TxReadWriteSet
	if err := proto.Unmarshal(ca.GetResults(), &txrw); err != nil {
		return nil, fmt.Errorf("read-write set: %w", err)
	}
	a := &Action{Chaincode: ca.GetChaincodeId().GetName(), Version: ca.GetChaincodeId().GetVersion()}
	for _, ns := range txrw.GetNsRwset() {
		if ns.GetNamespace() != a.Chaincode {
			continue
		}
		var kv kvrwset.KVRWSet
		if err := proto.Unmarshal(ns.GetRwset(), &kv); err != nil {
			return nil, fmt.Errorf("namespace %s: %w", ns.GetNamespace(), err)
		}
		for _, w := range kv.GetWrites() {
			a.Writes = append(a.Writes, Write{Key: w.GetKey(), Value: w.GetValue(), IsDelete: w.GetIsDelete()})
		}
	}
	return a, nil
}

// Find returns the write to key, if any.
func (a *Action) Find(key string) (Write, bool) {
	for _, w := range a.Writes {
		if w.Key == key {
			return w, true
		}
	}
	return Write{}, false
}

// Endorser is a decoded endorser identity.
type Endorser struct {
	MSPID string
	Cert  *x509.Certificate
}

// ParseIdentity decodes msp.SerializedIdentity bytes.
func ParseIdentity(b []byte) (*Endorser, error) {
	var sid msp.SerializedIdentity
	if err := proto.Unmarshal(b, &sid); err != nil {
		return nil, fmt.Errorf("serialized identity: %w", err)
	}
	blk, _ := pem.Decode(sid.GetIdBytes())
	if blk == nil {
		return nil, errors.New("identity holds no PEM certificate")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity certificate: %w", err)
	}
	return &Endorser{MSPID: sid.GetMspid(), Cert: cert}, nil
}

// VerifyEndorsement checks sig over SHA-256(prp || endorser) with the
// endorser's own key. It does not check the certificate chain; see parties.
func VerifyEndorsement(prp, endorser, sig []byte) (*Endorser, error) {
	id, err := ParseIdentity(endorser)
	if err != nil {
		return nil, err
	}
	pub, ok := id.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return id, errors.New("endorser key is not ECDSA")
	}
	digest := sha256.Sum256(append(append([]byte{}, prp...), endorser...))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return id, errors.New("signature does not verify")
	}
	return id, nil
}
