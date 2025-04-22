package main

import (
	"fmt"

	"github.com/etclab/pre"
	"github.com/etclab/samba"
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

	key := pre.KdfGtToAes256(m)
	ct := samba.AESGCMEncrypt(key, []byte("Hello, World!"))

	key1 := pre.KdfGtToAes256(m1)
	pt1, err := samba.AESGCMDecrypt(key1, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pt1))

	key2 := pre.KdfGtToAes256(m2)
	pt2, err := samba.AESGCMDecrypt(key2, ct)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(pt2))
}
