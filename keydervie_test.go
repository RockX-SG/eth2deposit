package eth2deposit

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	seed0, _ = new(big.Int).SetString("0xc55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", 0)
	seed1, _ = new(big.Int).SetString("0x3141592653589793238462643383279502884197169399375105820974944592", 0)
	seed2, _ = new(big.Int).SetString("0x0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00", 0)
	seed3, _ = new(big.Int).SetString("0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", 0)

	master_SK0, _ = new(big.Int).SetString("6083874454709270928345386274498605044986640685124978867557563392430687146096", 10)
	master_SK1, _ = new(big.Int).SetString("29757020647961307431480504535336562678282505419141012933316116377660817309383", 10)
	master_SK2, _ = new(big.Int).SetString("27580842291869792442942448775674722299803720648445448686099262467207037398656", 10)
	master_SK3, _ = new(big.Int).SetString("19022158461524446591288038168518313374041767046816487870552872741050760015818", 10)

	child_SK_0, _          = new(big.Int).SetString("20397789859736650942317412262472558107875392172444076792671091975210932703118", 10)
	child_SK_3141592653, _ = new(big.Int).SetString("25457201688850691947727629385191704516744796114925897962676248250929345014287", 10)
	child_SK_4294967295, _ = new(big.Int).SetString("29358610794459428860402234341874281240803786294062035874021252734817515685787", 10)
	child_SK_42, _         = new(big.Int).SetString("31372231650479070279774297061823572166496564838472787488249775572789064611981", 10)
)

func Test_IKM_to_lamport_SK(t *testing.T) {
	salt := []byte("test")
	ikm := []byte("this is a secret")
	lamport_sk, err := _IKM_to_lamport_SK(ikm, salt)
	assert.Nil(t, err)

	for k := range lamport_sk {
		t.Log(hex.EncodeToString(lamport_sk[k]))
	}
	t.Log("total chunk:", len(lamport_sk))
}

func Test_parent_SK_to_lamport_PK(t *testing.T) {
	randKey := make([]byte, 32)
	io.ReadFull(rand.Reader, randKey)
	key := new(big.Int).SetBytes(randKey)
	compressed_pk, err := _parent_SK_to_lamport_PK(key, 0)
	assert.Nil(t, err)
	t.Log(hex.EncodeToString(compressed_pk))
}

func Test_HKDF_mod_r(t *testing.T) {
	randIKM := make([]byte, 32)
	io.ReadFull(rand.Reader, randIKM)
	r := _HKDF_mod_r(randIKM, []byte(""))
	t.Log(r)
}

func TestKeyDerive(t *testing.T) {
	_doTestDerive(t, seed0, master_SK0, child_SK_0, 0)
	_doTestDerive(t, seed1, master_SK1, child_SK_3141592653, 3141592653)
	_doTestDerive(t, seed2, master_SK2, child_SK_4294967295, 4294967295)
	_doTestDerive(t, seed3, master_SK3, child_SK_42, 42)
}

func _doTestDerive(t *testing.T, seed *big.Int, master_sk *big.Int, child_sk *big.Int, index uint32) {
	bts := seed.Bytes()
	if len(bts) < 32 {
		extend := make([]byte, 32)
		copy(extend[32-len(bts):], bts)
		bts = extend
	}

	r, err := _derive_master_SK(bts)
	assert.Nil(t, err)
	assert.Equal(t, master_sk, r)
	r, err = _derive_child_SK(r, index)
	assert.Nil(t, err)
	assert.Equal(t, child_sk, r)
}
