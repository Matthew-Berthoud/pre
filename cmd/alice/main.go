package main

import (
	"github.com/etclab/pre/internal/samba"
)

const (
	PROXY samba.InstanceId = "http://localhost:8080"
	ALICE samba.InstanceId = "http://localhost:8081"
)

func main() {
	samba.BootFunction(ALICE, PROXY)
}
