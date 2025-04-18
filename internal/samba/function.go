package samba

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"

	"github.com/etclab/pre"
)

var (
	pp      *pre.PublicParams
	keyPair *pre.KeyPair
)

func genReEncryptionKey(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("Failed to read request body: %v", err)
		return
	}

	var rkReq ReEncryptionKeyRequest
	if err := json.Unmarshal(body, &rkReq); err != nil {
		http.Error(w, "Invalid request format", http.StatusBadRequest)
		log.Printf("Invalid request format: %v", err)
		return
	}

	pk, err := DeSerializePublicKey(rkReq.PublicKeySerialzed)
	if err != nil {
		http.Error(w, "Failed to deserialize public key", http.StatusBadRequest)
		log.Printf("Failed to deserialize public key: %v", err)
		return
	}

	rkAB := pre.ReEncryptionKeyGen(pp, keyPair.SK, &pk)
	rks := SerializeReEncryptionKey(*rkAB)
	response := ReEncryptionKeyMessage{
		InstanceId:                rkReq.InstanceId,
		ReEncryptionKeySerialized: rks,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Failed to encode response: %v", err)
	}
}

func handleMessage(w http.ResponseWriter, req *http.Request) {
	HandleMessage(w, req, keyPair, pp)
}

func port(id InstanceId) string {
	re := regexp.MustCompile(`:\d+`)
	return re.FindString(string(id))
}

func BootFunction(selfId, proxyId InstanceId) {
	pp = FetchPublicParams(proxyId)
	keyPair = pre.KeyGen(pp)
	RegisterPublicKey(proxyId, selfId, keyPair.PK)

	http.HandleFunc("/requestReEncryptionKey", genReEncryptionKey)
	http.HandleFunc("/message", handleMessage)

	port := port(selfId)
	log.Println("Alice service running on " + port)
	log.Fatal(http.ListenAndServe(port, nil))
}
