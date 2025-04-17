package samba

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	bls "github.com/cloudflare/circl/ecc/bls12381"
	"github.com/etclab/pre"
)

func fetch[T any](fullUrl string) T {
	u, err := url.Parse(fullUrl)
	if err != nil {
		panic(fmt.Sprintf("Invalid URL: %v", err))
	}
	resp, err := http.Get(u.String())
	if err != nil {
		panic(fmt.Sprintf("Failed to fetch: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		panic(fmt.Sprintf("Fetching returned status %d, body: %s",
			resp.StatusCode, body))
	}

	var t T
	if err := json.NewDecoder(resp.Body).Decode(&t); err != nil {
		panic(fmt.Sprintf("Failed to decode: %v", err))
	}

	return t
}

func FetchPublicParams(proxyId InstanceId) *pre.PublicParams {
	fullUrl := fmt.Sprintf("%s/publicParams", proxyId)
	m := fetch[PublicParamsSerialized](fullUrl)
	pp, err := DeSerializePublicParams(m)
	if err != nil {
		panic(fmt.Sprintf("Failed to deserialize public params: %v", err))
	}
	return &pp
}

func FetchPublicKey(proxyId InstanceId, functionId FunctionId) *pre.PublicKey {
	fullUrl := fmt.Sprintf("%s/publicKey?functionId=%d", proxyId, functionId)
	m := fetch[PublicKeySerialized](fullUrl)
	pk, err := DeSerializePublicKey(m)
	if err != nil {
		panic(fmt.Sprintf("Failed to deserialize public key: %v", err))
	}
	return &pk
}

func RegisterPublicKey(proxyId, instanceId InstanceId, pk *pre.PublicKey) {
	fullUrl := fmt.Sprintf("%s/registerPublicKey?instanceId=%s", proxyId, instanceId)
	pks := SerializePublicKey(*pk)
	body, err := json.Marshal(pks)
	if err != nil {
		log.Fatalf("Failed to marshal serialized public key: %v", err)
	}

	resp, err := http.Post(fullUrl, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Fatalf("Failed to post public key: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("RegisterPublicKey returned non-OK status: %d", resp.StatusCode)
	}
}

func SendMessage(m SambaMessage, instanceId InstanceId) (response *http.Response, err error) {
	reqBody, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(string(instanceId)+"/message", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	return resp, nil
}

func HandleMessage(w http.ResponseWriter, req *http.Request, keyPair *pre.KeyPair, pp *pre.PublicParams) {
	defer req.Body.Close()
	body, err := io.ReadAll(req.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Printf("Failed to read request body: %v", err)
		return
	}

	var m SambaMessage
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "Invalid message format", http.StatusBadRequest)
		log.Printf("Invalid message format: %v", err)
		return
	}

	var gt *bls.Gt
	if m.IsReEncrypted {
		ct2, err := DeSerializeCiphertext2(m.WrappedKey2)
		if err != nil {
			http.Error(w, "Failed to deserialize Ciphertext2", http.StatusBadRequest)
			log.Printf("Failed to deserialize Ciphertext2: %v", err)
			return
		}
		log.Printf("Decrypting with method 2, with re-encryption")
		gt = pre.Decrypt2(pp, &ct2, keyPair.SK)
	} else {
		ct1, err := DeSerializeCiphertext1(m.WrappedKey1)
		if err != nil {
			http.Error(w, "Failed to deserialize Ciphertext1", http.StatusBadRequest)
			log.Printf("Failed to deserialize Ciphertext1: %v", err)
			return
		}
		log.Printf("Decrypting with method 1, without re-encryption")
		gt = pre.Decrypt1(pp, &ct1, keyPair.SK)
	}
	key := pre.KdfGtToAes256(gt)
	plaintext, err := pre.AESGCMDecrypt(key, m.Ciphertext)
	if err != nil {
		http.Error(w, "Error performing AES Decryption: %v", http.StatusInternalServerError)
		log.Printf("Error performing AES Decryption: %v", err)
	}

	result := strings.ToUpper(string(plaintext))
	w.Write([]byte(result))
}
