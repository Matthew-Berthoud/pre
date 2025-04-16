package main

import (
	//"bytes"
	"encoding/json"
	"fmt"
	"strconv"

	//"io"
	"log"
	"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const ALICE samba.InstanceId = "http://localhost:8081"
const BOB samba.InstanceId = "http://localhost:8082"

var pp *pre.PublicParams = pre.NewPublicParams()
var functionLeaders = make(map[samba.FunctionId]samba.InstanceId)
var keys = make(map[samba.InstanceId]samba.InstanceKeys)

func recvPublicKey(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var pks samba.PublicKeySerialized
	err := json.NewDecoder(req.Body).Decode(&pks)
	if err != nil {
		log.Printf("Failed to decode public key: %v", err)
		http.Error(w, "Failed to decode public key", http.StatusBadRequest)
		return
	}

	pk, err := samba.DeSerializePublicKey(pks)
	if err != nil {
		log.Printf("Failed to deserialize public key: %v", err)
		http.Error(w, "Failed to deserialize public key", http.StatusBadRequest)
		return
	}

	instanceId := samba.InstanceId(req.PathValue("instanceId"))
	setPublicKey(instanceId, pk)
	log.Printf("Successfully storing public key for instanceId: %s", instanceId)

	w.WriteHeader(http.StatusOK)
}

func setPublicKey(instanceId samba.InstanceId, pk pre.PublicKey) {
	keys[instanceId] = samba.InstanceKeys{
		PublicKey:       pk,
		ReEncryptionKey: keys[instanceId].ReEncryptionKey, // Preserve existing re-encryption key if resetting
	}
}

func sendPublicParams(w http.ResponseWriter, req *http.Request) {
	pps, err := samba.SerializePublicParams(*pp)
	if err != nil {
		http.Error(w, "Failed to serialize fields in public parameters", http.StatusInternalServerError)
		log.Printf("Failed to serialize fields in public parameters")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(pps)
	if err != nil {
		http.Error(w, "Failed to encode and respond with public parameters", http.StatusInternalServerError)
		log.Printf("Failed to encode and respond with public parameters")
		return
	}
}

//func aliceBusy() bool {
//	return true
//}
//
//func genReEncryptionKey(a, b samba.InstanceId) (pre.ReEncryptionKey, error) {
//	if keys[b].ReEncryptionKey != (pre.ReEncryptionKey{}) {
//		return keys[b].ReEncryptionKey, nil
//	}
//
//	pk := keys[b].PublicKey
//
//	req := samba.ReEncryptionKeyRequest{
//		InstanceId: b,
//		PublicKey:  pk,
//	}
//	body, err := json.Marshal(req)
//	if err != nil {
//		return pre.ReEncryptionKey{}, err
//	}
//
//	resp, err := http.Post(string(a)+"/requestReEncryptionKey", "application/json", bytes.NewReader(body))
//	if err != nil {
//		return pre.ReEncryptionKey{}, err
//	}
//	defer resp.Body.Close()
//
//	if resp.StatusCode != http.StatusOK {
//		return pre.ReEncryptionKey{}, fmt.Errorf("requestReEncryptionKey failed with status %d", resp.StatusCode)
//	}
//
//	var rkMsg samba.ReEncryptionKeyMessage
//	if err := json.NewDecoder(resp.Body).Decode(&rkMsg); err != nil {
//		return pre.ReEncryptionKey{}, err
//	}
//
//	rk := rkMsg.ReEncryptionKey
//	instanceKeys := keys[rkMsg.InstanceId]
//	instanceKeys.ReEncryptionKey = rk
//	keys[rkMsg.InstanceId] = instanceKeys
//	return rk, nil
//}

func getOrSetLeader(functionId samba.FunctionId) samba.InstanceId {
	if functionLeaders[functionId] == "" {
		// in the real implementation there would be some better way to select a leader
		functionLeaders[functionId] = ALICE
	}
	leaderId := functionLeaders[functionId]
	log.Printf("Function with ID: %d has Leader replica with ID: %s", functionId, leaderId)
	return leaderId
}

//func recvMessage(w http.ResponseWriter, req *http.Request) {
//	defer req.Body.Close()
//	body, err := io.ReadAll(req.Body)
//	if err != nil {
//		http.Error(w, "Failed to read request body", http.StatusBadRequest)
//		log.Printf("Failed to read request body: %v", err)
//		return
//	}
//
//	var encryptedMessage samba.EncryptedMessage
//	if err := json.Unmarshal(body, &encryptedMessage); err != nil {
//		http.Error(w, "Invalid message format", http.StatusBadRequest)
//		log.Printf("Invalid message format: %v", err)
//		return
//	}
//
//	log.Printf("MWB proxy recvMessage encryptedMessage: %v", encryptedMessage.Message)
//	functionId := encryptedMessage.FunctionId
//	leaderId := getOrSetLeader(functionId)
//
//	ct1 := &encryptedMessage.Message
//
//	var resp *http.Response
//	if aliceBusy() {
//		rkAB, err := genReEncryptionKey(leaderId, BOB)
//		if err != nil {
//			http.Error(w, "Failed to get re-encryption key: "+err.Error(), http.StatusInternalServerError)
//			log.Printf("Failed to get re-encryption key: %v", err)
//			return
//		}
//		ct2 := pre.ReEncrypt(pp, &rkAB, ct1)
//		m := samba.ReEncryptedMessage{Message: *ct2}
//		resp, err = samba.SendMessage(m, BOB)
//	} else {
//		m := encryptedMessage
//		resp, err = samba.SendMessage(m, ALICE)
//	}
//
//	if err != nil {
//		http.Error(w, "Message forwarding failed: "+err.Error(), http.StatusInternalServerError)
//		log.Printf("Message forwarding failed: %v", err)
//		return
//	}
//
//	// Forward final response to original sender
//	defer resp.Body.Close()
//	w.WriteHeader(resp.StatusCode)
//	if _, err := io.Copy(w, resp.Body); err != nil {
//		log.Printf("Failed to write response body: %v", err)
//	}
//}

func sendPublicKey(w http.ResponseWriter, req *http.Request) {
	functionId, err := strconv.ParseUint(req.PathValue("functionId"), 10, 64)
	if err != nil {
		fmt.Println("Error parsing string to uint:", err)
		return
	}

	leaderId := getOrSetLeader(samba.FunctionId(functionId))
	leaderKeys, exists := keys[leaderId]
	if !exists {
		http.Error(w, "Function leader has no public key", http.StatusInternalServerError)
		log.Printf("Function leader has no public key for leaderId %s", leaderId)
		return
	}

	msg := samba.SerializePublicKey(leaderKeys.PublicKey)
	jsonData, err := json.Marshal(msg)
	if err != nil {
		http.Error(w, "Failed to encode public key", http.StatusInternalServerError)
		log.Printf("Error marshaling public key message: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write(jsonData)
	if err != nil {
		log.Printf("Error writing response: %v", err)
	}
}

func main() {
	http.HandleFunc("/publicParams", sendPublicParams)
	http.HandleFunc("/registerPublicKey", recvPublicKey)
	http.HandleFunc("/publicKey", sendPublicKey)
	//http.HandleFunc("/message", recvMessage)
	log.Println("Proxy service running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
