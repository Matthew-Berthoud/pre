package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const (
	PROXY samba.InstanceId = "http://localhost:8080"
	ALICE samba.InstanceId = "http://localhost:8081"
	BOB   samba.InstanceId = "http://localhost:8082"
)

var (
	pp    *pre.PublicParams
	alice *pre.KeyPair
)

func handle1(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var encMsg samba.EncryptedMessage
	if err := json.Unmarshal(body, &encMsg); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		return
	}

	// Decrypt directly using Alice's secret key
	decrypted := pre.Decrypt1(pp, &encMsg.Message, alice.SK)

	// Create response struct
	response := samba.SambaPlaintext{Message: *decrypted}

	// Marshal and send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func genReEncryptionKey(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var rkReq samba.ReEncryptionKeyRequest
	if err := json.Unmarshal(body, &rkReq); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		return
	}

	rkAB := pre.ReEncryptionKeyGen(pp, alice.SK, &rkReq.PublicKey)
	response := samba.ReEncryptionKeyMessage{
		InstanceId:      BOB,
		ReEncryptionKey: *rkAB,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func main() {
	// Fetch public parameters from proxy
	pp = samba.GetPublicParams(PROXY)
	alice = pre.KeyGen(pp)
	samba.RegisterPublicKey(PROXY, BOB, *alice.PK)

	http.HandleFunc("/genReEncryptionKey", genReEncryptionKey)

	http.HandleFunc("/message", handle1)

	log.Println("Alice service running on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
