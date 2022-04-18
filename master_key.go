package eth2deposit

import (
	"crypto/elliptic"
	"crypto/sha256"
	"fmt"
	"runtime"

	hmac "github.com/RockX-SG/eth2deposit/hmac"
	"github.com/awnumar/memguard"
)

const (
	SeedLength  = 32
	encTemplate = "rockx.com/key_derive/%v"
)

// MasterKey defines an enclaved master key for offering online service
type MasterKey struct {
	enclave *memguard.Enclave
	curve   elliptic.Curve
}

// NewMasterKey creates an encalved key
func NewMasterKey(seed [SeedLength]byte) *MasterKey {
	mk := new(MasterKey)
	mk.enclave = memguard.NewEnclave(seed[:])
	mk.curve = elliptic.P256()
	return mk
}

// DeriveChild derives crypto-strong child key
//
// Approach:
//
// For Each Level of Subkey Generation:
// 	secret := hmac(rockx.com/eth/key_id/%v(string), parentKey)
// 	pubkey := p256.ScalaBaseMult(secret)
//	childKey := hash(pubkey)
func (mkey *MasterKey) DeriveChild(path string) (*memguard.LockedBuffer, error) {
	defer runtime.GC()
	nodes, err := _path_to_nodes(path)
	if err != nil {
		return nil, err
	}

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

// derive the n-th child of parent key
func (mkey *MasterKey) _derive_child(parentKey *memguard.LockedBuffer, id uint32) (*memguard.LockedBuffer, error) {
	defer parentKey.Destroy()
	// path string
	message := fmt.Sprintf(encTemplate, id)

	// hmac-sha256
	mac := hmac.New(sha256.New, parentKey.Bytes())
	mac.Write([]byte(message))
	sum := mac.Sum(nil)
	defer mac.Reset()
	defer mac.Wipe()
	defer wipeSlice(sum)

	// priv -> pub
	X, Y := mkey.curve.ScalarBaseMult(sum[:])

	// hash(pub)
	h := sha256.New()
	defer h.Reset()

	tmp := make([]byte, 32)
	X.FillBytes(tmp)
	h.Write(tmp)
	defer wipeBig(X)

	tmp = make([]byte, 32)
	Y.FillBytes(tmp)
	h.Write(tmp)
	defer wipeBig(Y)

	return memguard.NewBufferFromBytes(h.Sum(nil)), nil
}
