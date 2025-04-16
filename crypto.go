package pre

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/etclab/mu"
)

const KeySize = 32
const NonceSize = 12

func RSAEncrypt(pub *rsa.PublicKey, msg []byte) []byte {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)
	if err != nil {
		mu.Panicf("failed to RSA encrypt: %v", err)
	}
	return ciphertext
}

func RSADecrypt(priv *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
}

func NewAESGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		mu.Panicf("aes.NewCipher failed: %v", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		mu.Panicf("cipher.NewGCM failed: %v", err)
	}

	return aesgcm
}

func AESGCMEncrypt(key, plaintext []byte) []byte {
	aesgcm := NewAESGCM(key)
	nonce := make([]byte, NonceSize) // zero nonce
	return aesgcm.Seal(plaintext[:0], nonce, plaintext, nil)
}

func AESGCMDecrypt(key, ciphertext []byte) ([]byte, error) {
	aesgcm := NewAESGCM(key)
	nonce := make([]byte, NonceSize) // zero nonce
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
