package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const PROXY samba.InstanceId = "http://localhost:8080"
const FUNCTION_ID samba.FunctionId = 123

func randomGt() *bls.Gt {
	a := pre.RandomScalar()
	b := pre.RandomScalar()

	g1 := bls.G1Generator()
	g2 := bls.G2Generator()

	g1.ScalarMult(a, g1)
	g2.ScalarMult(b, g2)

	z := bls.Pair(g1, g2)
	return z
}

func main() {
	// NOTE: obviously this isn't plaintext, how to make this work on normal plaintext again?
	// Look back at lily's rust implementation, I think I made some notes there.
	m := randomGt()

	// request public params from proxy
	pp := samba.GetPublicParams(PROXY)

	// request function leader's public key from proxy
	alicePK := samba.RequestPublicKey(PROXY, FUNCTION_ID)

	// encrypt message to alice
	ct1 := pre.Encrypt(pp, m, &alicePK)

	req := samba.EncryptedMessage{
		Message:    *ct1,
		FunctionId: FUNCTION_ID,
	}

	body, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("failed to marshal: %v", err)
	}

	// send ciphertext to proxy
	resp, err := http.Post(string(PROXY)+"/message", "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("Sending ct1 to proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Samba Request failed with status: %v and Response Body: %v", resp.Status, resp.Body)
	}

	var result samba.SambaPlaintext
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("Failed to decode SambaPlaintext: %v", err)
	}

	m1 := result.Message
	fmt.Println(m1.IsEqual(m))
}
