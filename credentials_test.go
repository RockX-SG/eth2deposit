package main

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	seed, _                  = new(big.Int).SetString("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", 16)
	master_SK, _             = new(big.Int).SetString("6083874454709270928345386274498605044986640685124978867557563392430687146096", 10)
	path                     = "m/0"
	child_index              = 0
	compressed_lamport_PK, _ = new(big.Int).SetString("dd635d27d1d52b9a49df9e5c0c622360a4dd17cba7db4e89bce3cb048fb721a5", 16)
	child_SK, _              = new(big.Int).SetString("20397789859736650942317412262472558107875392172444076792671091975210932703118", 10)
)

func Test_seed_and_path_to_key(t *testing.T) {
	sk, err := _seed_and_path_to_key(seed, path)
	assert.Nil(t, err)
	assert.Equal(t, child_SK, sk)
	t.Log(sk)
}

func TestSK(t *testing.T) {
	cred, err := NewCredential(seed, 0, nil)
	assert.Nil(t, err)
	t.Log(cred.WithdrawalSK())
	t.Log(cred.SigningSK())
}

func TestPK(t *testing.T) {
	cred, err := NewCredential(seed, 0, nil)
	assert.Nil(t, err)

	pub, err := cred.SigningPK()
	assert.Nil(t, err)
	t.Log("signing public key:", hex.EncodeToString(pub))

	pub, err = cred.WithdrawalPK()
	assert.Nil(t, err)
	t.Log("withdrawal public key:", hex.EncodeToString(pub))
	//	bts, err := pk.MarshalBinary()
	//	assert.Nil(t, err)
}

func TestETHCrendentials(t *testing.T) {
	account, _ := new(big.Int).SetString("0x0ce20f2274F4260eFC0D3FD4d736581C403d52Ba", 0)
	cred, err := NewCredential(seed, 0, account.Bytes())
	assert.Nil(t, err)
	tp, err := cred.withdrawType()
	assert.Nil(t, err)
	assert.EqualValues(t, ETH1_ADDRESS_WITHDRAWAL, tp)

	bts, err := cred.WithdrawCredentials()
	assert.Nil(t, err)
	t.Log("eth 1 withdraw crendentials:", hex.EncodeToString(bts))

	msg, err := cred.depositMessage()
	assert.Nil(t, err)
	root, err := msg.HashTreeRoot()
	assert.Nil(t, err)
	t.Log("deposit message root:", hex.EncodeToString(root[:]))

	signed, err := cred.signedDeposit()
	assert.Nil(t, err)
	root, err = signed.HashTreeRoot()
	assert.Nil(t, err)
	t.Log("signed deposit message root:", hex.EncodeToString(root[:]))
	t.Log("signature:", hex.EncodeToString(signed.Signature))
}

func TestBLSCrendentials(t *testing.T) {
	cred, err := NewCredential(seed, 0, nil)
	assert.Nil(t, err)
	tp, err := cred.withdrawType()
	assert.Nil(t, err)
	assert.EqualValues(t, BLS_WITHDRAWAL, tp)

	bts, err := cred.WithdrawCredentials()
	assert.Nil(t, err)
	t.Log("bls withdraw crendentials:", hex.EncodeToString(bts))

	msg, err := cred.depositMessage()
	assert.Nil(t, err)
	root, err := msg.HashTreeRoot()
	assert.Nil(t, err)
	t.Log("deposit message root:", hex.EncodeToString(root[:]))

	signed, err := cred.signedDeposit()
	assert.Nil(t, err)
	root, err = signed.HashTreeRoot()
	assert.Nil(t, err)
	t.Log("signed deposit message root:", hex.EncodeToString(root[:]))
	t.Log("signature:", hex.EncodeToString(signed.Signature))
}
