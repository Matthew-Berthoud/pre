package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const ALICE samba.InstanceId = "http://localhost:8081"
const BOB samba.InstanceId = "http://localhost:8082"

var pp *pre.PublicParams = pre.NewPublicParams()
var keys = make(map[samba.InstanceId]*samba.InstanceKeys)
var functionLeaders = make(map[samba.FunctionId]samba.InstanceId)

func sendPublicParams(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	err := json.NewEncoder(w).Encode(pp)
	if err != nil {
		http.Error(w, "Failed to encode public parameters", http.StatusInternalServerError)
		return
	}
}

func recvPublicKey(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var pkMessage samba.PublicKeyMessage
	if err := json.Unmarshal(body, &pkMessage); err != nil {
		http.Error(w, "Invalid public key format", http.StatusBadRequest)
		return
	}

	keys[pkMessage.InstanceId].PublicKey = pkMessage.PublicKey

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

	var rkMsg samba.ReEncryptionKeyMessage
	if err := json.NewDecoder(resp.Body).Decode(&rkMsg); err != nil {
		return pre.ReEncryptionKey{}, err
	}

	rk := rkMsg.ReEncryptionKey
	keys[rkMsg.InstanceId].ReEncryptionKey = rk
	return rk, nil
}

func recvMessage(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var encryptedMessage samba.EncryptedMessage
	if err := json.Unmarshal(body, &encryptedMessage); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		return
	}

	functionId := encryptedMessage.FunctionId
	leaderId := functionLeaders[functionId]

	ct1 := &encryptedMessage.Message

	var resp *http.Response
	if aliceBusy() {
		rkAB, err := genReEncryptionKey(leaderId, BOB)
		if err != nil {
			http.Error(w, "Failed to get re-encryption key: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ct2 := pre.ReEncrypt(pp, &rkAB, ct1)
		m := samba.ReEncryptedMessage{Message: *ct2}
		resp, err = sendSambaMessage(m, BOB)
	} else {
		m := samba.EncryptedMessage{Message: *ct1}
		resp, err = sendSambaMessage(m, ALICE)
	}

	if err != nil {
		http.Error(w, "Message forwarding failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Forward final response to original sender
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(w, resp.Body); err != nil {
		log.Printf("Failed to write response body: %v", err)
	}
}

func main() {
	http.HandleFunc("/getPublicParams", sendPublicParams)
	http.HandleFunc("/registerPublicKey", recvPublicKey)
	http.HandleFunc("/message", recvMessage)
	http.ListenAndServe(":8080", nil)
}
