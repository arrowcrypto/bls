package bls

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	msg  = []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	salt = []byte{11, 12, 13, 14}
)

func TestBasicFunctions(t *testing.T) {
	req := require.New(t)

	blsPrivateKey, err := GenerateKeyPair()
	req.NoError(err)
	req.NotNil(blsPrivateKey)

	blsPublicKey := blsPrivateKey.GetPublicKey()
	req.NotNil(blsPublicKey)
	newGx := blsPublicKey.gx.ScalarMult(blsPublicKey.gx, new(big.Int).SetInt64(1))
	req.Equal(blsPublicKey.gx, newGx)

	sig := Sign(blsPrivateKey, msg, salt)
	req.NotNil(sig)

	newSigma := sig.sigma.ScalarMult(sig.sigma, new(big.Int).SetInt64(1))
	req.Equal(newSigma, sig.sigma)

	verified := Verify(blsPublicKey, msg, salt, sig)
	req.Equal(true, verified)
}

func TestAggregatedSignatures(t *testing.T) {
	req := require.New(t)

	pubKeys := make([]*PublicKey, 0)
	sigs := make([]*Signature, 0)

	// Generate key pairs and sign messages
	for i := 0; i < 10; i++ {
		newPrivateKey, err := GenerateKeyPair()
		req.NoError(err)
		req.NotNil(newPrivateKey)
		pubKeys = append(pubKeys, newPrivateKey.GetPublicKey())

		sig := Sign(newPrivateKey, msg, salt)
		req.NotNil(sig)
		sigs = append(sigs, sig)

		verified := Verify(pubKeys[i], msg, salt, sig)
		req.Equal(true, verified)
	}

	// Aggregate public keys and signatures
	aggSig := AggregateSignatures(sigs[0])
	aggPubKey := AggregatePublicKeys(pubKeys[0])
	for i := 1; i < 10; i++ {
		aggSig = AggregateSignatures(aggSig, sigs[i])
		req.NotNil(aggSig)
		aggPubKey = AggregatePublicKeys(aggPubKey, pubKeys[i])
		req.NotNil(aggPubKey)
	}

	verified := Verify(aggPubKey, msg, salt, aggSig)
	req.Equal(true, verified)

	verified = Verify(pubKeys[0], msg, salt, aggSig)
	req.Equal(false, verified)
}
