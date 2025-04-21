package main

import (
	"github.com/etclab/pre/internal/samba"
)

func main() {
	var proxyId samba.InstanceId = "http://localhost:8080"
	var aliceId samba.InstanceId = "http://localhost:8081"
	samba.BootFunction(aliceId, proxyId)
}
