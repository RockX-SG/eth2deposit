package main

import (
	"encoding/hex"
	"testing"
)

func TestIKMtoLamportSK(t *testing.T) {
	salt := []byte("test")
	ikm := []byte("this is a secret")
	lamport_sk := IKM_to_lamport_SK(ikm, salt)

	for k := range lamport_sk {
		t.Log(hex.EncodeToString(lamport_sk[k]))
	}
	t.Log("total chunk:", len(lamport_sk))
}
