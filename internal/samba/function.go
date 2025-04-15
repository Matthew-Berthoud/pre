package samba

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"

	"github.com/etclab/pre"
)

func GetPublicParams(proxyId InstanceId) (pp *pre.PublicParams) {
	resp, err := http.Get(string(proxyId) + "/getPublicParams")
	if err != nil {
		log.Fatalf("Failed to fetch public parameters: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Received non-200 status: %d", resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(&pp); err != nil {
		log.Fatalf("Failed to decode public parameters: %v", err)
	}
	return pp
}

func RegisterPublicKey(proxyId, id InstanceId, pk pre.PublicKey) {
	pkMsg := PublicKeyMessage{
		InstanceId: id,
		PublicKey:  pk,
	}

	body, err := json.Marshal(pkMsg)
	if err != nil {
		log.Fatalf("Failed to marshal public key message: %v", err)
	}
	resp, err := http.Post(
		string(proxyId)+"/registerPublicKey",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		log.Fatalf("Failed to register public key: %v", err)
	}
	defer resp.Body.Close()
}

func RequestPublicKey(proxyId InstanceId, functionId FunctionId) pre.PublicKey {
	req := PublicKeyRequest{FunctionId: functionId}
	reqBody, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("Failed to Marshal public key request: %v", err)
	}

	resp, err := http.Post(string(proxyId)+"/getPublicKey", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		log.Fatalf("Failed to send public key request: %v", err)
	}

	defer resp.Body.Close()
	var pkMsg PublicKeyMessage
	if err := json.NewDecoder(resp.Body).Decode(&pkMsg); err != nil {
		log.Fatalf("Failed to decode public key response: %v", err)
	}

	return pkMsg.PublicKey
}
