package bls

import (
	"bytes"
	"crypto/rand"
	"math/big"

	"github.com/cloudflare/bn256"
)

var (
	one   = new(big.Int).SetInt64(1)
	g2gen = new(bn256.G2).ScalarBaseMult(big.NewInt(1))
)

// PublicKey is the BLS public key, i.e. a point on curve G2
type PublicKey struct {
	gx *bn256.G2
}

// Private key is a scalar
type PrivateKey struct {
	PublicKey
	x *big.Int
}

// Signature is a point on G1
type Signature struct {
	sigma *bn256.G1
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

	return bytes.Compare(rhs.Marshal(), lhs.Marshal()) == 0
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
