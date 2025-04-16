package main

import (
	"fmt"

	"github.com/etclab/pre"
)

func main() {
	pp := pre.NewPublicParams()

	alice := pre.KeyGen(pp)
	bob := pre.KeyGen(pp)
	rkAB := pre.ReEncryptionKeyGen(pp, alice.SK, bob.PK)

	m := pre.RandomGt()
	ct1 := pre.Encrypt(pp, m, alice.PK)
	ct2 := pre.ReEncrypt(pp, rkAB, ct1)

	m1 := pre.Decrypt1(pp, ct1, alice.SK)
	m2 := pre.Decrypt2(pp, ct2, bob.SK)

	fmt.Println(m1.IsEqual(m))
	fmt.Println(m1.IsEqual(m2))
}
