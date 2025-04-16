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
