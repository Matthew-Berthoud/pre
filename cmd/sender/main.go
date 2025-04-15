package main

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const PROXY samba.InstanceId = "http://localhost:8080"
const FUNCTION_ID samba.FunctionId = 123

func randomGt() *bls.Gt {
	a := pre.RandomScalar()
	b := pre.RandomScalar()

	g1 := bls.G1Generator()
	g2 := bls.G2Generator()

	g1.ScalarMult(a, g1)
	g2.ScalarMult(b, g2)

	z := bls.Pair(g1, g2)
	return z
}

func main() {
	// NOTE: obviously this isn't plaintext, how to make this work on normal plaintext again?
	// Look back at lily's rust implementation, I think I made some notes there.
	m := randomGt()

	// request public params from proxy
	pp := samba.GetPublicParams(PROXY)

	// request function leader's public key from proxy
	alicePK := samba.RequestPublicKey(PROXY, FUNCTION_ID)

	// encrypt message to alice

	//ct1 := pre.Encrypt(pp, m, &alicePK)
	pre.Encrypt(pp, m, &alicePK)

	// send ciphertext to proxy

	// wait for response from proxy
	// print response
}
