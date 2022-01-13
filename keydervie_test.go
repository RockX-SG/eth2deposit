package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"
)

func Test_IKM_to_lamport_SK(t *testing.T) {
	salt := []byte("test")
	ikm := []byte("this is a secret")
	lamport_sk := _IKM_to_lamport_SK(ikm, salt)

	for k := range lamport_sk {
		t.Log(hex.EncodeToString(lamport_sk[k]))
	}
	t.Log("total chunk:", len(lamport_sk))
}

func Test_parent_SK_to_lamport_PK(t *testing.T) {
	randKey := make([]byte, 32)
	io.ReadFull(rand.Reader, randKey)
	key := new(big.Int).SetBytes(randKey)
	compressed_pk := _parent_SK_to_lamport_PK(key, 0)
	t.Log(hex.EncodeToString(compressed_pk))
}

func Test_HKDF_mod_r(t *testing.T) {
	randIKM := make([]byte, 32)
	io.ReadFull(rand.Reader, randIKM)
	r := _HKDF_mod_r(randIKM, []byte(""))
	t.Log(r)
}
