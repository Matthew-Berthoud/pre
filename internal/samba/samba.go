package samba

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/pre"
)

/*
The proxy needs to maintain two dictionaries:
- function -> cur leader (instance ID)
- instance id -> pubkey, re-encrypt key

Message types:
(also need A's public key I think)
1. B -> P: registerPubKey(Bid, Bpubkey)
2. P -> A: genReencryptionKey(Bid, Bpubkey)
3. A -> P: registerReencryptionKey(Bid, RkAB)
4. B -> P: get Reenctyptionkey(Bid) ??? do we need this

*/

type FunctionId uint
type InstanceId string // represents a url for now, potentially change to uint

type InstanceKeys struct {
	PublicKey       pre.PublicKey
	ReEncryptionKey pre.ReEncryptionKey
}

type PublicKeyRequest struct {
	FunctionId FunctionId
}

type PublicKeyMessage struct {
	InstanceId InstanceId
	PublicKey  pre.PublicKey
}

type ReEncryptionKeyRequest struct {
	InstanceId InstanceId
	PublicKey  pre.PublicKey
}

type ReEncryptionKeyMessage struct {
	InstanceId      InstanceId
	ReEncryptionKey pre.ReEncryptionKey
}

type EncryptedMessage struct {
	FunctionId FunctionId
	Message    pre.Ciphertext1
}

type ReEncryptedMessage struct {
	FunctionId FunctionId
	Message    pre.Ciphertext2
}

type SambaMessage interface {
	EncryptedMessage | ReEncryptedMessage
}

type SambaPlaintext struct {
	FunctionId FunctionId
	Message    bls.Gt
}
