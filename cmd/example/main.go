package main

import (
	"crypto/rand"
	"fmt"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/pre"
)

func randomScalar() *bls.Scalar {
	z := new(bls.Scalar)
	z.Random(rand.Reader)
	return z
}

func randomGt() *bls.Gt {
	a := randomScalar()
	b := randomScalar()

	g1 := bls.G1Generator()
	g2 := bls.G2Generator()

	g1.ScalarMult(a, g1)
	g2.ScalarMult(b, g2)

	z := bls.Pair(g1, g2)
	return z
}

func main() {
	pp := pre.NewPublicParams()

	alice := pre.KeyGen(pp)
	bob := pre.KeyGen(pp)
	rkAB := pre.ReEncryptionKeyGen(pp, alice.SK, bob.PK)

	m := randomGt()
	ct1 := pre.Encrypt(pp, m, alice.PK)
	ct2 := pre.ReEncrypt(pp, rkAB, ct1)

	m1 := pre.Decrypt1(pp, ct1, alice.SK)
	m2 := pre.Decrypt2(pp, ct2, bob.SK)

	fmt.Println(m1.IsEqual(m))
	fmt.Println(m1.IsEqual(m2))
}
