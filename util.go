package pre

import bls "github.com/cloudflare/circl/ecc/bls12381"

const DST_G2 = "QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_"
const DST_G1 = "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_"

// hash arbitrary message ([]byte) to bls.Gt
// based on: https://github.com/cloudflare/circl/blob/main/ecc/bls12381/hash_test.go
func HashMsgGt(msg []byte) *bls.Gt {
	g1 := new(bls.G1)
	g1.Hash(msg, []byte(DST_G1))
	g2 := new(bls.G2)
	g2.Hash(msg, []byte(DST_G2))
	return bls.Pair(g1, g2)
}
