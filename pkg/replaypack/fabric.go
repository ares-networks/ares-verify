package replaypack

import (
	"crypto/sha256"
	"strings"

	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/rwset/kvrwset"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"
)

// KVWrite is one write in a transaction's write set.
type KVWrite struct {
	Key      string
	Value    []byte
	IsDelete bool
}

// BuildPRP builds ProposalResponsePayload{proposal_hash, extension:
// ChaincodeAction{results: TxReadWriteSet{KV, [NsReadWriteSet{namespace:
// chaincode, rwset: KVRWSet{writes}}]}, chaincode_id{name, version},
// response{200}}}.
func BuildPRP(chaincode, txID string, writes []KVWrite) ([]byte, error) {
	kv := &kvrwset.KVRWSet{}
	for _, w := range writes {
		kv.Writes = append(kv.Writes, &kvrwset.KVWrite{Key: w.Key, Value: w.Value, IsDelete: w.IsDelete})
	}
	kvb, err := proto.Marshal(kv)
	if err != nil {
		return nil, err
	}
	txrw, err := proto.Marshal(&rwset.TxReadWriteSet{
		DataModel: rwset.TxReadWriteSet_KV,
		NsRwset:   []*rwset.NsReadWriteSet{{Namespace: chaincode, Rwset: kvb}},
	})
	if err != nil {
		return nil, err
	}
	ca, err := proto.Marshal(&peer.ChaincodeAction{
		Results:     txrw,
		ChaincodeId: &peer.ChaincodeID{Name: chaincode, Version: "1.0"},
		Response:    &peer.Response{Status: 200},
	})
	if err != nil {
		return nil, err
	}
	ph := sha256.Sum256([]byte("proposal:" + txID))
	return proto.Marshal(&peer.ProposalResponsePayload{ProposalHash: ph[:], Extension: ca})
}

// CompositeKey lays out a ledger composite key: U+0000, the object type,
// U+0000, the attributes joined by U+0000, then a final U+0000.
func CompositeKey(objectType string, attrs ...string) string {
	return "\x00" + objectType + "\x00" + strings.Join(attrs, "\x00") + "\x00"
}
