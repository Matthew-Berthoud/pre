package main

import (
	//"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	//"log"
	//"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const PROXY samba.InstanceId = "http://localhost:8080"
const FUNCTION_ID samba.FunctionId = 123

func main() {

	message := []byte("Hello, World!")

	// request public params from proxy
	pp := samba.FetchPublicParams(PROXY)

	// request function leader's public key from proxy
	alicePK := samba.FetchPublicKey(PROXY, FUNCTION_ID)

	m := pre.RandomGt()
	ct1 := pre.Encrypt(pp, m, alicePK)

	key := pre.KdfGtToAes256(m)
	ct := pre.AESGCMEncrypt(key, message)
	ct1s, err := samba.SerializeCiphertext1(*ct1)
	if err != nil {
		log.Fatalf("Failed to serialize: %v", err)
	}

	req := samba.SambaMessage{
		Target:        FUNCTION_ID,
		IsReEncrypted: false,
		WrappedKey1:   ct1s,
		Ciphertext:    ct,
	}
	resp, err := samba.SendMessage(req, PROXY)
	if err != nil {
		log.Fatalf("Sending to proxy failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Samba Request failed with status: %v", resp.Status)
	}

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	fmt.Printf("Sent message: %s\n", message)
	fmt.Printf("Uppercase version: %s\n", result)
}
