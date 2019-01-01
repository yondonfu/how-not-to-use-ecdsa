package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// TrickSig1 uses a given valid signature (r, s) over a message hash
// to calculate another valid signature over the same message hash as (r, -s mod n)
// where n is the curve order i.e. the order of the base point
func TrickSig1(r, s *big.Int, curve elliptic.Curve) (*big.Int, *big.Int) {
	return r, ScalarNeg(s, curve)
}

// TrickSig2 uses a given public key to calculate a valid signature and hash pair
// using the following algorithm:
//
// G = base point of curve
// P = public key
// R = aG + bP
// (r, s) = (R.x, R.x / b)
// hash = R.x * a / b
//
// The resulting pair will not pass proper ECDSA verification because the verifier
// should hash the input message first BEFORE checking the signature. If the verifier
// is not implemented in this way, then the result of this function
// would pass verification
func TrickSig2(pubKey ecdsa.PublicKey) (*big.Int, *big.Int, []byte) {
	curve := pubKey.Curve
	N := curve.Params().N

	// Calculate aG
	a := big.NewInt(5)
	xAG, yAG := curve.ScalarBaseMult(a.Bytes())

	// Calculate bP
	b := big.NewInt(17)
	xBP, yBP := curve.ScalarMult(pubKey.X, pubKey.Y, b.Bytes())

	// Calculate R = aG + bP
	xR, _ := curve.Add(xAG, yAG, xBP, yBP)

	// Calculate the new signature (R.x, R.x / b)
	bInv := new(big.Int).ModInverse(b, N)
	r := new(big.Int).Mod(xR, N)
	s := new(big.Int).Mod(new(big.Int).Mul(r, bInv), N)

	// Calculate the new message hash R.x * a / b
	inter := new(big.Int).Mod(new(big.Int).Mul(r, a), N)
	hash := new(big.Int).Mod(new(big.Int).Mul(inter, bInv), N)

	return r, s, hash.Bytes()
}

// ScalarNeg negates a scalar modulo the curve order
func ScalarNeg(scalar *big.Int, curve elliptic.Curve) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(scalar), curve.Params().N)
}

func main() {
	// Generate private key
	// Using the secp256k1 curve
	privKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// Message to be signed
	msg := "hello world"
	// Hash message to be signed
	hash := sha256.Sum256([]byte(msg))

	// Sign message hash using private key
	r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
	if err != nil {
		panic(err)
	}

	fmt.Printf("original sig: (0x%x, 0x%x)\n", r, s)

	if ecdsa.Verify(&privKey.PublicKey, hash[:], r, s) {
		fmt.Printf("original sig verification with message hash 0x%x: SUCCESS\n", hash[:])
	} else {
		fmt.Printf("original sig verification with message hash 0x%x: FAILED\n", hash[:])
	}

	fmt.Println()

	trickR1, trickS1 := TrickSig1(r, s, crypto.S256())

	fmt.Printf("trick sig 1: (0x%x, 0x%x)\n", trickR1, trickS1)

	fmt.Printf("NO MALLEABILITY CHECK\n")

	if ecdsa.Verify(&privKey.PublicKey, hash[:], trickR1, trickS1) {
		fmt.Printf("trick sig 1 verification with message hash 0x%x: SUCCESS\n", hash[:])
	} else {
		fmt.Printf("trick sig 1 verification with message hash 0x%x: FAILED\n", hash[:])
	}

	fmt.Println()

	fmt.Printf("WITH MALLEABILITY CHECK\n")

	halfCurveOrder := new(big.Int).Div(crypto.S256().Params().N, big.NewInt(2))
	fmt.Printf("HALF CURVE ORDER = %x\n", halfCurveOrder)

	if trickS1.Cmp(halfCurveOrder) > 0 {
		fmt.Printf("trick sig 1 s-value > half curve order!\n")
	} else {
		fmt.Printf("trick sig 1 s-value <= half curve order!\n")
		fmt.Printf("normalizing sig by negating s-value\n")

		trickS1 = ScalarNeg(trickS1, crypto.S256())
	}

	trickSig := append(trickR1.Bytes(), trickS1.Bytes()...)

	if crypto.VerifySignature(crypto.CompressPubkey(&privKey.PublicKey), hash[:], trickSig) {
		fmt.Printf("trick sig 1 verification with message hash 0x%x: SUCCESS\n", hash[:])
	} else {
		fmt.Printf("trick sig 1 verification with message hash 0x%x: FAILED\n", hash[:])
	}

	fmt.Println()

	trickR2, trickS2, trickHash2 := TrickSig2(privKey.PublicKey)

	fmt.Printf("trick sig 2: (0x%x, 0x%x)\n", trickR2, trickS2)

	if ecdsa.Verify(&privKey.PublicKey, trickHash2, trickR2, trickS2) {
		fmt.Printf("trick sig 2 verification with message hash 0x%x: SUCCESS\n", trickHash2)
	} else {
		fmt.Printf("trick sig 2 verification with message hash 0x%x: FAILED\n", trickHash2)
	}
}
