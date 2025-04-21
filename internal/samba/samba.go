package samba

import (
	"github.com/etclab/pre"
)

type InstanceId string // represents a url for now, potentially change to uint
type FunctionId uint

type SambaMessage struct {
	Target        FunctionId            `json:"target"`
	IsReEncrypted bool                  `json:"is_re_encrypted"`
	WrappedKey1   Ciphertext1Serialized `json:"wrapped_key1,omitempty"` // Encrypted bls.Gt that derives to AES key
	WrappedKey2   Ciphertext2Serialized `json:"wrapped_key2,omitempty"` // Re-encrypted bls.Gt that derives to AES key
	Ciphertext    []byte                `json:"ciphertext"`             // plaintext (just a string for now) encrypted under the AES key
}

type InstanceKeys struct {
	PublicKey       pre.PublicKey       `json:"public_key"`
	ReEncryptionKey pre.ReEncryptionKey `json:"re_encryption_key"`
}

type PublicKeyRequest struct {
	FunctionId FunctionId `json:"function_id"`
}

type ReEncryptionKeyRequest struct {
	InstanceId         InstanceId          `json:"instance_id"`
	PublicKeySerialzed PublicKeySerialized `json:"public_key_serialized"`
}

type ReEncryptionKeyMessage struct {
	InstanceId                InstanceId                `json:"instance_id"`
	ReEncryptionKeySerialized ReEncryptionKeySerialized `json:"re_encryption_key_serialized"`
}
