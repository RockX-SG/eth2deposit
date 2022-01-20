package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/awnumar/memguard"
)

const (
	pbkdf2_salt = "dc7b47c157efcef2170669a3b5386b96550cdd0db5c28bb4cbdbba79c0196f0c"
	seedLength  = 32
	encTemplate = "rockx.com/eth2/key_id/%v"
)

type MasterKey struct {
	enclave *memguard.Enclave
}

func NewMasterKey(seed [seedLength]byte) *MasterKey {
	mk := new(MasterKey)
	mk.enclave = memguard.NewEnclave(seed[:])
	return mk
}

// derive the N-th id with current master key with specified key size
func (mkey *MasterKey) CreateCredential(id uint64) (*Credential, error) {
	// Approach:
	// String-> Hash(String) -> Encrypt with seed
	content := fmt.Sprintf(encTemplate, id)
	sum := sha256.Sum256([]byte(content))

	// open master key in enclave
	b, err := mkey.enclave.Open()
	if err != nil {
		return nil, err
	}
	defer b.Destroy()

	// encrypt
	aesBlock, err := NewAESBlockCrypt(b.Bytes())
	if err != nil {
		return nil, err
	}
	aesBlock.Encrypt(sum[:], sum[:])

	// the result will be used as credential key
	seed := new(big.Int).SetBytes(sum[:])
	return NewCredential(seed, 0, nil)
}
