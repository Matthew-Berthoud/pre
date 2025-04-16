package main

import (
	//"encoding/json"
	"fmt"
	//"log"
	//"net/http"

	"github.com/etclab/pre"
	"github.com/etclab/pre/internal/samba"
)

const PROXY samba.InstanceId = "http://localhost:8080"
const FUNCTION_ID samba.FunctionId = 123

func main() {

	// request public params from proxy
	pp := samba.FetchPublicParams(PROXY)

	// request function leader's public key from proxy
	alicePK := samba.FetchPublicKey(PROXY, FUNCTION_ID)

	m := pre.RandomGt()
	ct1 := pre.Encrypt(pp, m, alicePK)

	fmt.Println(ct1)

	//	req := samba.EncryptedMessage{
	//		Message:    *ct1,
	//		FunctionId: FUNCTION_ID,
	//	}
	//
	// log.Printf("MWB sender encryptedmessage: %v", req)
	//
	// // send ciphertext to proxy
	// resp, err := samba.SendMessage(req, PROXY)
	//
	//	if err != nil {
	//		log.Fatalf("Sending ct1 to proxy failed: %v", err)
	//	}
	//
	// defer resp.Body.Close()
	//
	//	if resp.StatusCode != http.StatusOK {
	//		log.Fatalf("Samba Request failed with status: %v and Response Body: %v", resp.Status, resp.Body)
	//	}
	//
	// var result samba.SambaPlaintext
	//
	//	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
	//		log.Fatalf("Failed to decode SambaPlaintext: %v", err)
	//	}
	//
	// m2 := result.Message
	// didItWork := m2.IsEqual(m)
	// fmt.Println(didItWork)
	//
	//	if !didItWork {
	//		fmt.Printf("ORIGINAL MESSAGE: %v\n", m)
	//		fmt.Printf("ECHOED   MESSAGE: %v\n", m2)
	//	}
}
