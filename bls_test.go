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

	// Test key generation
	blsPrivateKey, err := GenerateKeyPair()
	req.NoError(err)
	req.NotNil(blsPrivateKey)

	blsPublicKey := blsPrivateKey.GetPublicKey()
	req.NotNil(blsPublicKey)
	newGx := blsPublicKey.gx.ScalarMult(blsPublicKey.gx, new(big.Int).SetInt64(1))
	req.Equal(blsPublicKey.gx, newGx)

	// Test Sign
	sigInBytes, err := Sign(nil, msg, salt)
	req.Error(err)
	req.Nil(sigInBytes)

	sigInBytes, err = Sign(blsPrivateKey, nil, salt)
	req.Error(err)
	req.Nil(sigInBytes)

	sigInBytes, err = Sign(blsPrivateKey, msg, nil)
	req.Error(err)
	req.Nil(sigInBytes)

	sigInBytes, err = Sign(blsPrivateKey, msg, salt)
	req.NoError(err)
	req.NotNil(sigInBytes)

	sig := new(Signature)
	err = sig.FromBytes(sigInBytes)
	req.NoError(err)

	// Test key serialization and deserialization
	pubKeyInBytes := blsPublicKey.ToBytes()
	blsPublicKey = new(PublicKey)
	err = blsPublicKey.FromBytes(pubKeyInBytes)
	req.NoError(err)

	pubKeyInBytes = []byte{0}
	badPublicKey := new(Signature)
	err = badPublicKey.FromBytes(pubKeyInBytes)
	req.Error(err)

	pubKeyInHex := blsPublicKey.ToHex()
	blsPublicKey = new(PublicKey)
	err = blsPublicKey.FromHex(pubKeyInHex)
	req.NoError(err)

	pubKeyInHex = "1224"
	badPublicKey = new(Signature)
	err = badPublicKey.FromHex(pubKeyInHex)
	req.Error(err)

	privKeyInBytes := blsPrivateKey.ToBytes()
	blsPrivateKey = new(PrivateKey)
	err = blsPrivateKey.FromBytes(privKeyInBytes)
	req.NoError(err)

	privKeyInHex := blsPrivateKey.ToHex()
	blsPrivateKey = new(PrivateKey)
	err = blsPrivateKey.FromHex(privKeyInHex)
	req.NoError(err)

	// Test Verify with recovered keys
	newSigma := sig.sigma.ScalarMult(sig.sigma, new(big.Int).SetInt64(1))
	req.Equal(newSigma, sig.sigma)

	err = Verify(nil, msg, salt, sig.ToBytes())
	req.Error(err)

	err = Verify(blsPublicKey, nil, salt, sig.ToBytes())
	req.Error(err)

	err = Verify(blsPublicKey, msg, nil, sig.ToBytes())
	req.Error(err)

	err = Verify(blsPublicKey, msg, salt, nil)
	req.Error(err)

	err = Verify(blsPublicKey, msg, salt, sig.ToBytes())
	req.NoError(err)

	sigInBytes = sig.ToBytes()
	newSig := new(Signature)
	err = newSig.FromBytes(sigInBytes)
	req.NoError(err)

	sigInBytes = []byte{0}
	badSig := new(Signature)
	err = badSig.FromBytes(sigInBytes)
	req.Error(err)

	err = Verify(blsPrivateKey.GetPublicKey(), msg, salt, newSig.ToBytes())
	req.NoError(err)

	sigInHex := sig.ToHex()
	newSig = new(Signature)
	err = newSig.FromHex(sigInHex)
	req.NoError(err)

	err = Verify(blsPrivateKey.GetPublicKey(), msg, salt, newSig.ToBytes())
	req.NoError(err)

	sigInHex = "1234"
	badSig = new(Signature)
	err = badSig.FromHex(sigInHex)
	req.Error(err)
}

func TestAggregatedSignatures(t *testing.T) {
	req := require.New(t)

	pubKeys := make([]*PublicKey, 0)
	sigs := make([]*Signature, 0)

	// Generate key pairs and sign messages
	for i := 0; i < 10; i++ {
		var err error
		newPrivateKey, err := GenerateKeyPair()
		req.NoError(err)
		req.NotNil(newPrivateKey)
		pubKeys = append(pubKeys, newPrivateKey.GetPublicKey())

		sig, err := Sign(newPrivateKey, msg, salt)
		req.NoError(err)
		req.NotNil(sig)

		newSig := new(Signature)
		err = newSig.FromBytes(sig)
		req.NoError(err)
		sigs = append(sigs, newSig)

		err = Verify(pubKeys[i], msg, salt, sig)
		req.NoError(err)
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

	err := Verify(aggPubKey, msg, salt, aggSig.ToBytes())
	req.NoError(err)

	err = Verify(pubKeys[0], msg, salt, aggSig.ToBytes())
	req.Error(err)

	// Aggregate a single key twice
	aggPubKey = AggregatePublicKeys(aggPubKey, pubKeys[1])
	err = Verify(aggPubKey, msg, salt, aggSig.ToBytes())
	req.Error(err)

	// Aggregate the corresponding signture once more
	aggSig = AggregateSignatures(aggSig, sigs[1])
	err = Verify(aggPubKey, msg, salt, aggSig.ToBytes())
	req.NoError(err)

	aggPubKey = AggregatePublicKeys(aggPubKey, pubKeys[2])
	err = Verify(aggPubKey, msg, salt, aggSig.ToBytes())
	req.Error(err)

	aggSig = AggregateSignatures(aggSig, sigs[3])
	err = Verify(aggPubKey, msg, salt, aggSig.ToBytes())
	req.Error(err)
}
