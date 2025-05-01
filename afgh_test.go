package pre

import (
	"os"
	"testing"

	bls "github.com/cloudflare/circl/ecc/bls12381"
)

var blackhole any
var pp *PublicParams
var msg *bls.Gt
var alice *KeyPair
var bob *KeyPair
var ct1 *Ciphertext1
var ct2 *Ciphertext2
var rkAB *ReEncryptionKey

func TestMain(m *testing.M) {
	pp = NewPublicParams()

	alice = KeyGen(pp)
	bob = KeyGen(pp)
	rkAB = ReEncryptionKeyGen(pp, alice.SK, bob.PK)

	msg = RandomGt()
	ct1 = Encrypt(pp, msg, alice.PK)
	ct2 = ReEncrypt(pp, rkAB, ct1)

	exitVal := m.Run()
	os.Exit(exitVal)
}

func BenchmarkEncrypt(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blackhole = Encrypt(pp, msg, alice.PK)
	}
}

func BenchmarkReEncrypt(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blackhole = ReEncryptionKeyGen(pp, alice.SK, bob.PK)
	}
}

func BenchmarkDecrypt1(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blackhole = Decrypt1(pp, ct1, alice.SK)
	}
}

func BenchmarkDecrypt2(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blackhole = Decrypt2(pp, ct2, bob.SK)
	}
}

func BenchmarkKdfGtToAes256(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blackhole = KdfGtToAes256(msg)
	}
}
