package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// MasterKey defines an enclaved master key for offering online service
type MasterKey struct {
	enclave *memguard.Enclave
}

// NewMasterKey creates an encalved key
func NewMasterKey(seed [seedLength]byte) *MasterKey {
	mk := new(MasterKey)
	mk.enclave = memguard.NewEnclave(seed[:])
	return mk
}

// derive the N-th id with current master key
// Approach:
// String-> Hash(String) -> Encrypt with seed -> elliptic ScalaMult -> Hash(Point)
func (mkey *MasterKey) DeriveChild(id uint64) (*memguard.LockedBuffer, error) {
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

	//  calc Public Key
	var priv ecdsa.PrivateKey
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(sum[:])
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(priv.D.Bytes())

	// dervied seed from (X,Y)
	h := sha256.New()
	tmp := make([]byte, 32)
	priv.PublicKey.X.FillBytes(tmp)
	h.Write(tmp)

	tmp = make([]byte, 32)
	priv.PublicKey.Y.FillBytes(tmp)
	h.Write(tmp)

	return memguard.NewBufferFromBytes(h.Sum(nil)), nil
}
