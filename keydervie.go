package main

import (
	"crypto/sha256"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

const (
	K = 32
	L = K * 255
)

func _IKM_to_lamport_SK(IKM []byte, salt []byte) [][]byte {
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

func _parent_SK_to_lamport_PK(parent_SK *big.Int, index uint32) []byte {
	salt := make([]byte, 4)
	IKM := make([]byte, K)

	big.NewInt(int64(index)).FillBytes(salt)
	parent_SK.FillBytes(IKM)

	lamport_0 := _IKM_to_lamport_SK(IKM, salt)
	_flip_bits(IKM)
	lamport_1 := _IKM_to_lamport_SK(IKM, salt)
	var lamport_PK []byte

	for i := 0; i < len(lamport_0); i++ {
		sum := sha256.Sum256(lamport_0[i])
		lamport_PK = append(lamport_PK, sum[:]...)
	}

	for i := 0; i < len(lamport_1); i++ {
		sum := sha256.Sum256(lamport_1[i])
		lamport_PK = append(lamport_PK, sum[:]...)
	}

	compressed_lamport_PK := sha256.Sum256([]byte(lamport_PK))
	return compressed_lamport_PK[:]
}

func _flip_bits(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = ^in[i]
	}
}
