package main

import (
	"bytes"
	"encoding/json"
	"fmt"

	"io"
	"log"
	"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const ALICE samba.InstanceId = "http://localhost:8081"
const BOB samba.InstanceId = "http://localhost:8082"

var pp *pre.PublicParams = pre.NewPublicParams()
var keys = make(map[samba.InstanceId]samba.InstanceKeys)
var functionLeaders = make(map[samba.FunctionId]samba.InstanceId)

func sendPublicParams(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(pp)
	if err != nil {
		http.Error(w, "Failed to encode and respond with public parameters", http.StatusInternalServerError)
		log.Printf("Failed to encode and respond with public parameters: %v", err)
		return
	}
}

func recvPublicKey(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("Failed to read request body: %v", err)
		return
	}

	var pkMessage samba.PublicKeyMessage
	if err := json.Unmarshal(body, &pkMessage); err != nil {
		http.Error(w, "Invalid public key format", http.StatusBadRequest)
		log.Printf("Invalid public key format: %v", err)
		return
	}

	keys[pkMessage.InstanceId] = samba.InstanceKeys{
		PublicKey:       pkMessage.PublicKey,
		ReEncryptionKey: pre.ReEncryptionKey{},
	}

	w.WriteHeader(http.StatusOK)
}

func aliceBusy() bool {
	return true
}

func sendSambaMessage[T samba.SambaMessage](m T, destId samba.InstanceId) (response *http.Response, err error) {
	reqBody, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(string(destId)+"/message", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func genReEncryptionKey(a, b samba.InstanceId) (pre.ReEncryptionKey, error) {
	if keys[b].ReEncryptionKey != (pre.ReEncryptionKey{}) {
		return keys[b].ReEncryptionKey, nil
	}

	pk := keys[b].PublicKey

	req := samba.ReEncryptionKeyRequest{
		InstanceId: b,
		PublicKey:  pk,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return pre.ReEncryptionKey{}, err
	}

	resp, err := http.Post(string(a)+"/requestReEncryptionKey", "application/json", bytes.NewReader(body))
	if err != nil {
		return pre.ReEncryptionKey{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return pre.ReEncryptionKey{}, fmt.Errorf("requestReEncryptionKey failed with status %d", resp.StatusCode)
	}

	var rkMsg samba.ReEncryptionKeyMessage
	if err := json.NewDecoder(resp.Body).Decode(&rkMsg); err != nil {
		return pre.ReEncryptionKey{}, err
	}

	rk := rkMsg.ReEncryptionKey
	instanceKeys := keys[rkMsg.InstanceId]
	instanceKeys.ReEncryptionKey = rk
	keys[rkMsg.InstanceId] = instanceKeys
	return rk, nil
}

func getOrSetLeader(functionId samba.FunctionId) samba.InstanceId {
	if functionLeaders[functionId] == "" {
		// in the real implementation there would be some better way to select a leader
		functionLeaders[functionId] = ALICE
	}
	leaderId := functionLeaders[functionId]
	log.Printf("Function with ID: %d has Leader replica with ID: %s", functionId, leaderId)
	return leaderId
}

func recvMessage(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("Failed to read request body: %v", err)
		return
	}

	var encryptedMessage samba.EncryptedMessage
	if err := json.Unmarshal(body, &encryptedMessage); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		log.Printf("Invalid message format: %v", err)
		return
	}

	functionId := encryptedMessage.FunctionId
	leaderId := getOrSetLeader(functionId)

	ct1 := &encryptedMessage.Message

	var resp *http.Response
	if aliceBusy() {
		rkAB, err := genReEncryptionKey(leaderId, BOB)
		if err != nil {
			http.Error(w, "Failed to get re-encryption key: "+err.Error(), http.StatusInternalServerError)
			log.Printf("Failed to get re-encryption key: %v", err)
			return
		}
		ct2 := pre.ReEncrypt(pp, &rkAB, ct1)
		m := samba.ReEncryptedMessage{Message: *ct2}
		resp, err = sendSambaMessage(m, BOB)
	} else {
		m := encryptedMessage
		resp, err = sendSambaMessage(m, ALICE)
	}

	if err != nil {
		http.Error(w, "Message forwarding failed: "+err.Error(), http.StatusInternalServerError)
		log.Printf("Message forwarding failed: %v", err)
		return
	}

	// Forward final response to original sender
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("Failed to write response body: %v", err)
	}
}

func sendPublicKey(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("Failed to read request body: %v", err)
		return
	}

	var pkReq samba.PublicKeyRequest
	if err := json.Unmarshal(body, &pkReq); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		log.Printf("Invalid message format: %v", err)
		return
	}

	leaderId := getOrSetLeader(pkReq.FunctionId)
	key, exists := keys[leaderId]
	if !exists { // Adjust based on your PublicKey type
		http.Error(w, "Function leader has no public key", http.StatusInternalServerError)
		log.Printf("Function leader has no public key for leaderId %s", leaderId)
		return
	}

	m := samba.PublicKeyMessage{
		InstanceId: leaderId,
		PublicKey:  key.PublicKey,
	}

	resp, err := json.Marshal(m)
	if err != nil {
		http.Error(w, "Failed to marshal public key message", http.StatusInternalServerError)
		log.Printf("Failed to marshal public key message: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

func main() {
	http.HandleFunc("/getPublicParams", sendPublicParams)
	http.HandleFunc("/registerPublicKey", recvPublicKey)
	http.HandleFunc("/getPublicKey", sendPublicKey)
	http.HandleFunc("/message", recvMessage)
	log.Println("Proxy service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
