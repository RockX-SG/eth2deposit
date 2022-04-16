package eth2deposit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/awnumar/memguard"
)

const (
	SeedLength  = 32
	encTemplate = "rockx.com/eth2/key_id/%v"
)

// MasterKey defines an enclaved master key for offering online service
type MasterKey struct {
	enclave *memguard.Enclave
}

// NewMasterKey creates an encalved key
func NewMasterKey(seed [SeedLength]byte) *MasterKey {
	mk := new(MasterKey)
	mk.enclave = memguard.NewEnclave(seed[:])
	return mk
}

// DeriveChild derives crypto-strong child key
//
// Approach:
//
// For Each Level of Subkey Generation:
// 	keyString := rockx.com/eth/key_id/%v(string)->
// 	h := Hash(keyString) ->
//  secret := encrypt(parentKey,h)
// 	pubkey := p256.ScalaBaseMult(secret)
//	childKey := hash(pubkey)
func (mkey *MasterKey) DeriveChild(path string) (*memguard.LockedBuffer, error) {
	nodes := _path_to_nodes(path)

	// open master key in enclave
	b, err := mkey.enclave.Open()
	if err != nil {
		return nil, err
	}

	// recursively locate to subkey
	subkey := b
	for k := range nodes {
		subkey, err = mkey._derive_child(subkey, nodes[k])
		if err != nil {
			return nil, err
		}
	}

	return subkey, nil
}

func (mkey *MasterKey) _derive_child(parentKey *memguard.LockedBuffer, id uint32) (*memguard.LockedBuffer, error) {
	defer parentKey.Destroy()
	// path string
	content := fmt.Sprintf(encTemplate, id)
	sum := sha256.Sum256([]byte(content))

	// encrypt
	aesBlock, err := NewAESBlockCrypt(parentKey.Bytes())
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
