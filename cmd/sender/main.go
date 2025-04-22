package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/samba"
)

func main() {
	var proxyId samba.InstanceId = "http://localhost:8080"
	var functionId samba.FunctionId = 123

	message := []byte("Hello, World!")

	// request public params from proxy
	pp := samba.FetchPublicParams(proxyId)

	// request function leader's public key from proxy
	alicePK := samba.FetchPublicKey(proxyId, functionId)

	m := pre.RandomGt()
	ct1 := pre.Encrypt(pp, m, alicePK)

	key := pre.KdfGtToAes256(m)
	ct := samba.AESGCMEncrypt(key, message)
	ct1s, err := samba.SerializeCiphertext1(*ct1)
	if err != nil {
		log.Fatalf("Failed to serialize: %v", err)
	}

	req := samba.SambaMessage{
		Target:        functionId,
		IsReEncrypted: false,
		WrappedKey1:   ct1s,
		Ciphertext:    ct,
	}
	resp, err := samba.SendMessage(&req, proxyId)
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
