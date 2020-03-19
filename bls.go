package bls

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/cloudflare/bn256"
)

var (
	g2gen = new(bn256.G2).ScalarBaseMult(big.NewInt(1))
)

// PublicKey is the BLS public key, i.e. a point on curve G2
type PublicKey struct {
	gx *bn256.G2
}

// ToBytes serializes the BLS public key to byte array.
func (pubKey *PublicKey) ToBytes() []byte {
	return pubKey.gx.Marshal()
}

// ToHex outputs a public key in hex
func (pubKey *PublicKey) ToHex() string {
	inBytes := pubKey.ToBytes()
	return hex.EncodeToString(inBytes)
}

// FromBytes deserializes a BLS public key from byte array.
func (pubKey *PublicKey) FromBytes(bytes []byte) error {
	pubKey.gx = new(bn256.G2)
	if _, err := pubKey.gx.Unmarshal(bytes); err != nil {
		return fmt.Errorf("cannot parse public key: %s", err)
	}
	return nil
}

// FromHex deserializes a BLS public key from hex string.
func (pubKey *PublicKey) FromHex(hexstr string) error {
	inBytes, err := hex.DecodeString(hexstr)
	if err != nil {
		return fmt.Errorf("failed to convert a hex string to a BLS public key: %s",
			err)
	}
	return pubKey.FromBytes(inBytes)
}

// Private key is a scalar
type PrivateKey struct {
	PublicKey
	x *big.Int
}

// ToHex outputs a private key in hex
func (privKey *PrivateKey) ToHex() string {
	inBytes := privKey.ToBytes()
	return hex.EncodeToString(inBytes)
}

// ToBytes serializes the BLS private key to byte array.
func (privKey *PrivateKey) ToBytes() []byte {
	return privKey.x.Bytes()
}

// FromBytes deserializes the BLS private key from byte array.
func (privKey *PrivateKey) FromBytes(b []byte) error {
	privKey.x = new(big.Int).SetBytes(b)
	if privKey.x.Cmp(bn256.Order) >= 0 {
		return fmt.Errorf("BLS private key is out of range")
	}
	privKey.gx = new(bn256.G2).ScalarBaseMult(privKey.x)
	return nil
}

func (privKey *PrivateKey) FromHex(hexstr string) error {
	inBytes, err := hex.DecodeString(hexstr)
	if err != nil {
		return fmt.Errorf("failed to convert a hex string to a BLS private key: %s",
			err)
	}
	return privKey.FromBytes(inBytes)
}

// Signature is a point on G1
type Signature struct {
	sigma *bn256.G1
}

// ToHex outputs a BLS Signature in hex
func (sig *Signature) ToHex() string {
	inBytes := sig.ToBytes()
	return hex.EncodeToString(inBytes)
}

// ToBytes serializes a BLS Signature in bytes
func (sig *Signature) ToBytes() []byte {
	return sig.sigma.Marshal()
}

// FromBytes deserializes a BLS signature from byte array.
func (sig *Signature) FromBytes(bytes []byte) error {
	sig.sigma = new(bn256.G1)
	if _, err := sig.sigma.Unmarshal(bytes); err != nil {
		return fmt.Errorf("cannot parse the bls signature: %s", err)
	}
	return nil
}

// FromHex deserializes a BLS signature from hex string.
func (sig *Signature) FromHex(hexstr string) error {
	inBytes, err := hex.DecodeString(hexstr)
	if err != nil {
		return fmt.Errorf("failed to convert a hex string to a the bls signature: %s",
			err)
	}
	return sig.FromBytes(inBytes)
}

func (privKey *PrivateKey) GetPublicKey() *PublicKey {
	var pubKey PublicKey
	pubKey.gx = privKey.gx
	return &pubKey
}

func GenerateKeyPair() (*PrivateKey, error) {
	var privKey PrivateKey
	var err error
	privKey.x, privKey.gx, err = bn256.RandomG2(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func Sign(privKey *PrivateKey, msg, salt []byte) *Signature {

	hash := bn256.HashG1(msg, salt)
	sigma := hash.ScalarMult(hash, privKey.x)
	return &Signature{sigma: sigma}
}

func Verify(pubKey *PublicKey, msg, salt []byte, sig *Signature) bool {
	//  check e(sigma, g2) =? e(H(m), pk )
	h := bn256.HashG1(msg, salt)

	rhs := bn256.Pair(h, pubKey.gx)
	lhs := bn256.Pair(sig.sigma, g2gen)

	return bytes.Equal(rhs.Marshal(), lhs.Marshal())
}

// AggregateSignatures combines signatures
func AggregateSignatures(sigs ...*Signature) *Signature {

	var aggregrated *Signature
	for i, sig := range sigs {
		if i == 0 {
			aggregrated = &Signature{
				sigma: new(bn256.G1).Set(sig.sigma),
			}
		} else {
			aggregrated.sigma.Add(aggregrated.sigma, sig.sigma)
		}
	}
	return aggregrated
}

// AggregatePublicKeys combines public keys
func AggregatePublicKeys(pubKeys ...*PublicKey) *PublicKey {
	var aggregrated PublicKey
	for i, pubKey := range pubKeys {
		if i == 0 {
			aggregrated = PublicKey{
				gx: new(bn256.G2).Set(pubKey.gx),
			}
		} else {
			aggregrated.gx.Add(aggregrated.gx, pubKey.gx)
		}
	}
	return &aggregrated
}
