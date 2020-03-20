package main

import (
	"bls"
	"fmt"
	"time"
)

var (
	TIMES = int64(1000)
	msg   = []byte{1, 2, 3, 4, 5, 6}
	salt  = []byte{5, 6}
)

func main() {
	benchmark()
}

func benchmark() {

	publicKeys := make([]*bls.PublicKey, TIMES)
	privateKeys := make([]*bls.PrivateKey, TIMES)
	sigs := make([]*bls.Signature, TIMES)

	// Test key generation
	start := time.Now()
	for i := int64(0); i < TIMES; i++ {
		privateKeys[i], _ = bls.GenerateKeyPair()
	}
	end := time.Now()
	fmt.Printf("Average latency of BLS key generation is %v (us).\n",
		end.Sub(start).Microseconds()/TIMES)

	// Test Sign
	start = time.Now()
	for i := int64(0); i < TIMES; i++ {
		sigs[i] = bls.Sign(privateKeys[i], msg, salt)
	}
	end = time.Now()
	fmt.Printf("Average latency of BLS signature sign is %v (us).\n",
		end.Sub(start).Microseconds()/TIMES)

	for i := int64(0); i < TIMES; i++ {
		publicKeys[i] = privateKeys[i].GetPublicKey()
	}

	// Test verification
	start = time.Now()
	for i := int64(0); i < TIMES; i++ {
		if verified := bls.Verify(publicKeys[i], msg, salt, sigs[i]); !verified {
			panic("signature verification failed.")
		}
	}
	end = time.Now()
	fmt.Printf("Average latency of BLS signature verification is %v (us).\n",
		end.Sub(start).Microseconds()/TIMES)

	// Test signature aggregation
	aggSig := sigs[0]
	start = time.Now()
	for i := int64(1); i < TIMES; i++ {
		aggSig = bls.AggregateSignatures(aggSig, sigs[i])
	}
	end = time.Now()
	fmt.Printf("Latency of 999 BLS signatures aggregation is %v (us), i.e. "+
		" averagely %v (us).\n", end.Sub(start).Microseconds(),
		end.Sub(start).Microseconds()/(TIMES-1))

	// Test public key aggregation
	aggPubKey := publicKeys[0]

	start = time.Now()
	for i := int64(1); i < TIMES; i++ {
		aggPubKey = bls.AggregatePublicKeys(aggPubKey, publicKeys[i])
	}
	end = time.Now()
	fmt.Printf("Latency of 999 BLS public key aggregation is %v (us), i.e. "+
		" averagely %v (us).\n", end.Sub(start).Microseconds(),
		end.Sub(start).Microseconds()/(TIMES-1))

	if verified := bls.Verify(aggPubKey, msg, salt, aggSig); !verified {
		panic("aggregated signature verification failed.")
	}
}
