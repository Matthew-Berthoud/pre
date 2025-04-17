package samba

import (
	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/pre"
)

type PublicKeySerialized struct {
	G1toA []byte `json:"g1_to_a"`
	G2toA []byte `json:"g2_to_a"`
}

func SerializePublicKey(pk pre.PublicKey) PublicKeySerialized {
	return PublicKeySerialized{
		G1toA: pk.G1toA.Bytes(),
		G2toA: pk.G2toA.Bytes(),
	}
}

func DeSerializePublicKey(pks PublicKeySerialized) (pre.PublicKey, error) {
	g1 := &bls.G1{}
	g2 := &bls.G2{}

	err := g1.SetBytes(pks.G1toA)
	if err != nil {
		return pre.PublicKey{}, err
	}

	err = g2.SetBytes(pks.G2toA)
	if err != nil {
		return pre.PublicKey{}, err
	}

	pk := pre.PublicKey{
		G1toA: g1,
		G2toA: g2,
	}
	return pk, nil
}

type PublicParamsSerialized struct {
	G1 []byte `json:"g1"`
	G2 []byte `json:"g2"`
	Z  []byte `json:"z"`
}

func SerializePublicParams(pp pre.PublicParams) (PublicParamsSerialized, error) {
	z, err := pp.Z.MarshalBinary()
	if err != nil {
		return PublicParamsSerialized{}, err
	}

	pps := PublicParamsSerialized{
		G1: pp.G1.Bytes(),
		G2: pp.G2.Bytes(),
		Z:  z,
	}
	return pps, err
}

func DeSerializePublicParams(pps PublicParamsSerialized) (pre.PublicParams, error) {
	g1 := &bls.G1{}
	g2 := &bls.G2{}
	z := &bls.Gt{}

	err := g1.SetBytes(pps.G1)
	if err != nil {
		return pre.PublicParams{}, err
	}

	err = g2.SetBytes(pps.G2)
	if err != nil {
		return pre.PublicParams{}, err
	}

	err = z.UnmarshalBinary(pps.Z)
	if err != nil {
		return pre.PublicParams{}, err
	}

	pp := pre.PublicParams{
		G1: g1,
		G2: g2,
		Z:  z,
	}
	return pp, nil
}

type Ciphertext1Serialized struct {
	Alpha []byte
	Beta  []byte
}

func SerializeCiphertext1(ct1 pre.Ciphertext1) (Ciphertext1Serialized, error) {
	alpha, err := ct1.Alpha.MarshalBinary()
	if err != nil {
		return Ciphertext1Serialized{}, err
	}
	beta := ct1.Beta.Bytes()

	ct1s := Ciphertext1Serialized{
		Alpha: alpha,
		Beta:  beta,
	}

	return ct1s, nil
}

func DeSerializeCiphertext1(ct1s Ciphertext1Serialized) (pre.Ciphertext1, error) {
	alpha := &bls.Gt{}
	beta := &bls.G1{}

	err := alpha.UnmarshalBinary(ct1s.Alpha)
	if err != nil {
		return pre.Ciphertext1{}, err
	}

	err = beta.SetBytes(ct1s.Beta)
	if err != nil {
		return pre.Ciphertext1{}, err
	}

	ct1 := pre.Ciphertext1{
		Alpha: alpha,
		Beta:  beta,
	}
	return ct1, nil
}

type Ciphertext2Serialized struct {
	Alpha []byte
	Beta  []byte
}

func SerializeCiphertext2(ct2 pre.Ciphertext2) (Ciphertext2Serialized, error) {
	alpha, err := ct2.Alpha.MarshalBinary()
	if err != nil {
		return Ciphertext2Serialized{}, err
	}
	beta, err := ct2.Beta.MarshalBinary()
	if err != nil {
		return Ciphertext2Serialized{}, err
	}

	ct2s := Ciphertext2Serialized{
		Alpha: alpha,
		Beta:  beta,
	}

	return ct2s, nil
}

func DeSerializeCiphertext2(ct2s Ciphertext2Serialized) (pre.Ciphertext2, error) {
	alpha := &bls.Gt{}
	beta := &bls.Gt{}

	err := alpha.UnmarshalBinary(ct2s.Alpha)
	if err != nil {
		return pre.Ciphertext2{}, err
	}

	err = beta.UnmarshalBinary(ct2s.Beta)
	if err != nil {
		return pre.Ciphertext2{}, err
	}

	ct2 := pre.Ciphertext2{
		Alpha: alpha,
		Beta:  beta,
	}
	return ct2, nil
}
