package pre

import (
	"testing"
)

// Test same message hashes to same Gt
func TestSameMessage(t *testing.T) {
	fooMsg := []byte("foo world")
	h1 := HashMsgGt(fooMsg)
	h2 := HashMsgGt(fooMsg)

	if !h1.IsEqual(h2) {
		t.Errorf("Expected hashes to be equal")
	}
}

// Test different messages hashes to different Gt
func TestDifferentMessage(t *testing.T) {
	fooMsg := []byte("foo world")
	h1 := HashMsgGt(fooMsg)

	barMsg := []byte("bar world")
	h2 := HashMsgGt(barMsg)

	if h1.IsEqual(h2) {
		t.Errorf("Expected hashes to be different")
	}
}

// Test empty v. non-empty message hashes to different Gt
func TestEmptyMessage(t *testing.T) {
	fooMsg := []byte("foo world")
	h1 := HashMsgGt(fooMsg)

	emptyMsg := []byte("")
	h2 := HashMsgGt(emptyMsg)
	if h1.IsEqual(h2) {
		t.Errorf("Expected empty v. non-empty hashes to be different")
	}
}

// Test reencrypting a message
func TestReencrypt(t *testing.T) {
	pp := NewPublicParams()

	alice := KeyGen(pp)
	bob := KeyGen(pp)
	rkAB := ReEncryptionKeyGen(pp, alice.SK, bob.PK)

	msgBytes := []byte("foo world")
	m := HashMsgGt(msgBytes)
	ct1 := Encrypt(pp, m, alice.PK)
	ct2 := ReEncrypt(pp, rkAB, ct1)

	m1 := Decrypt1(pp, ct1, alice.SK)
	m2 := Decrypt2(pp, ct2, bob.SK)

	if !m1.IsEqual(m) {
		t.Errorf("Expected alice to decrypt encrypted msg correctly")
	}
	if !m1.IsEqual(m2) {
		t.Errorf("Expected bob to decrypt re-encrypted msg correctly")
	}
}
