package main

import (
	"github.com/etclab/pre/internal/samba"
)

func main() {
	var bobId samba.InstanceId = "http://localhost:8082"
	var proxyId samba.InstanceId = "http://localhost:8080"
	samba.BootFunction(bobId, proxyId)
}
