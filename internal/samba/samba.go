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
	PublicKey       pre.PublicKey       `json:"public_key"`
	ReEncryptionKey pre.ReEncryptionKey `json:"re_encryption_key"`
}

type PublicKeyRequest struct {
	FunctionId FunctionId `json:"function_id"`
}

type PublicKeyMessage struct {
	InstanceId InstanceId    `json:"instance_id"`
	PublicKey  pre.PublicKey `json:"public_key"`
}

type ReEncryptionKeyRequest struct {
	InstanceId InstanceId    `json:"instance_id"`
	PublicKey  pre.PublicKey `json:"public_key"`
}

type ReEncryptionKeyMessage struct {
	InstanceId      InstanceId          `json:"instance_id"`
	ReEncryptionKey pre.ReEncryptionKey `json:"re_encryption_key"`
}

type EncryptedMessage struct {
	FunctionId FunctionId      `json:"function_id"`
	Message    pre.Ciphertext1 `json:"message"`
}

type ReEncryptedMessage struct {
	FunctionId FunctionId      `json:"function_id"`
	Message    pre.Ciphertext2 `json:"message"`
}

type SambaMessage interface {
	EncryptedMessage | ReEncryptedMessage
}

type SambaPlaintext struct {
	FunctionId FunctionId `json:"function_id"`
	Message    bls.Gt     `json:"message"`
}
