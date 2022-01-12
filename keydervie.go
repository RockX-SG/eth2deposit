package main

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

func IKM_to_lamport_SK(IKM []byte, salt []byte) [][]byte {
	K := 32
	L := K * 255
	PRK := hkdf.Extract(sha256.New, []byte(IKM), []byte(salt))
	okmReader := hkdf.Expand(sha256.New, PRK, []byte(""))

	var lamport_SK [][]byte
	for i := 0; i < L/K; i++ {
		chunk := make([]byte, K)
		_, err := io.ReadFull(okmReader, chunk)
		if err != nil {
			panic(err)
		}

		lamport_SK = append(lamport_SK, chunk)
	}

	return lamport_SK
}
