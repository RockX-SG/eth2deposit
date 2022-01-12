package main

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func IKM_to_lamport_SK(IKM []byte, salt []byte) []byte {
	K := 32
	L := K * 255
	PRK := hkdf.Extract(sha256.New, []byte(IKM), []byte(salt))
	okmReader := hkdf.Expand(sha256.New, PRK, []byte(""))

	OKM := make([]byte, L)
	_, err := io.ReadFull(okmReader, OKM)
	if err != nil {
		panic(err)
	}

	return OKM
}
