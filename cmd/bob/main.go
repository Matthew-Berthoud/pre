package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const BOB samba.InstanceId = "http://localhost:8082"
const PROXY samba.InstanceId = "http://localhost:8080"

var (
	pp  *pre.PublicParams
	bob *pre.KeyPair
)

func handle2(w http.ResponseWriter, req *http.Request) {
	log.Printf("Bob handling re-encrypted message")

	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("Failed to read request body: %v", err)
		return
	}

	var reMsg samba.ReEncryptedMessage
	if err := json.Unmarshal(body, &reMsg); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		log.Printf("Invalid message format: %v", err)
		return
	}

	log.Printf("MWB bob re-encrypted message: %v", reMsg)

	// Decrypt re-encrypted message
	decrypted := pre.Decrypt2(pp, &reMsg.Message, bob.SK)

	log.Printf("MWB Bob sending re-encrypted message: %v", decrypted)

	// Create response struct
	response := samba.SambaPlaintext{Message: *decrypted}

	// Marshal and send response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func main() {
	// Handshake (get public parameters, send back public key)
	pp = samba.GetPublicParams(PROXY)
	bob = pre.KeyGen(pp)
	samba.RegisterPublicKey(PROXY, BOB, *bob.PK)

	http.HandleFunc("/message", handle2)

	log.Println("Bob service running on :8082")
	log.Fatal(http.ListenAndServe(":8082", nil))
}
