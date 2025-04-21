package main

import (
	"github.com/etclab/pre/internal/samba"
)

func main() {
	var aliceId samba.InstanceId = "http://localhost:8081"
	var bobId samba.InstanceId = "http://localhost:8082"
	samba.BootProxy([]samba.InstanceId{aliceId, bobId})
}
