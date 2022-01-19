package main

import (
	"crypto/sha256"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/herumi/bls-eth-go-binary/bls"
)

func init() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
}

func _path_to_nodes(path string) []uint32 {
	path = strings.ReplaceAll(path, " ", "")

	matched, err := regexp.MatchString("[m1234567890/]", path)
	if err != nil {
		panic(err)
	}

	if !matched {
		panic(fmt.Sprint("Invalid path:", path))
	}

	indices := strings.Split(path, "/")
	if indices[0] != "m" {
		panic(fmt.Sprint("The first character of path should be `m`. Got", indices[0]))
	}

	var indicesList []uint32
	for i := 1; i < len(indices); i++ {
		d, err := strconv.ParseUint(indices[i], 10, 32)
		if err != nil {
			panic(err)
		}

		indicesList = append(indicesList, uint32(d))
	}

	return indicesList

}

func _seed_and_path_to_key(seed *big.Int, path string) (*big.Int, error) {
	bts := seed.Bytes()
	if len(bts) < 32 {
		extend := make([]byte, 32)
		copy(extend[32-len(bts):], bts)
		bts = extend
	}

	sk, err := _derive_master_SK(bts)
	if err != nil {
		return nil, err
	}

	nodes := _path_to_nodes(path)
	for k := range nodes {
		sk, err = _derive_child_SK(sk, nodes[k])
		if err != nil {
			return nil, err
		}
	}
	return sk, nil
}

const (
	purpose   = "12381"
	coin_type = "3600"
)

type Credential struct {
	eth1_withdrawal_address []byte
	withdrawal_sk           *big.Int
	signing_sk              *big.Int
}

func NewCredential(seed *big.Int, account uint32, hex_eth1_withdrawal_address []byte) (*Credential, error) {
	cred := new(Credential)
	cred.eth1_withdrawal_address = hex_eth1_withdrawal_address
	withdrawal_key_path := fmt.Sprintf("m/%v/%v/%d/0", purpose, coin_type, account)
	withdrawal_sk, err := _seed_and_path_to_key(seed, withdrawal_key_path)
	if err != nil {
		return nil, err
	}
	cred.withdrawal_sk = withdrawal_sk

	signing_key_path := fmt.Sprintf("%s/0", withdrawal_key_path)
	signing_sk, err := _seed_and_path_to_key(seed, signing_key_path)
	if err != nil {
		return nil, err
	}
	cred.signing_sk = signing_sk

	return cred, nil
}

func (cred *Credential) WithdrawalSK() *big.Int { return cred.withdrawal_sk }
func (cred *Credential) SigningSK() *big.Int    { return cred.signing_sk }

func (cred *Credential) SigningPK() (pub []byte, err error) {
	sec := new(bls.SecretKey)
	err = sec.SetDecString(cred.signing_sk.Text(10))
	if err != nil {
		return nil, err
	}

	return sec.GetPublicKey().Serialize(), nil
}

func (cred *Credential) WithdrawalPK() (pub []byte, err error) {
	sec := new(bls.SecretKey)
	err = sec.SetDecString(cred.withdrawal_sk.Text(10))
	if err != nil {
		return nil, err
	}

	return sec.GetPublicKey().Serialize(), nil
}

func (cred *Credential) withdrawPrefix() byte {
	if cred.eth1_withdrawal_address != nil {
		return ETH1_ADDRESS_WITHDRAWAL_PREFIX
	}
	return BLS_WITHDRAWAL_PREFIX
}

func (cred *Credential) withdrawType() (WithdrawType, error) {
	prefix := cred.withdrawPrefix()
	if prefix == BLS_WITHDRAWAL_PREFIX {
		return BLS_WITHDRAWAL, nil
	} else if prefix == ETH1_ADDRESS_WITHDRAWAL_PREFIX {
		return ETH1_ADDRESS_WITHDRAWAL, nil
	}
	return INVALID_WITHDRAW, ErrorWithdrawPrefix
}

func (cred *Credential) depositMessage() (*DepositMessage, error) {
	msg := new(DepositMessage)
	pubkey, err := cred.SigningPK()
	if err != nil {
		return nil, err
	}

	withdrawCredential, err := cred.WithdrawCredentials()
	if err != nil {
		return nil, err
	}

	msg.Pubkey = pubkey
	msg.WithdrawalCredentials = withdrawCredential
	msg.Amount = uint64(1e9 * 32)

	return msg, nil
}

func (cred *Credential) signedDeposit() (*DepositData, error) {
	// deposit message
	depositMessage, err := cred.depositMessage()

	// deposit domain
	domain, err := compute_deposit_domain(MainnetSetting.GENESIS_FORK_VERSION)
	if err != nil {
		return nil, err
	}

	// signing root
	signingRoot := new(SigningData)
	copy(signingRoot.Domain[:], domain)
	objectRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	signingRoot.ObjectRoot = objectRoot

	// sign
	messageToSign, err := signingRoot.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	sec := new(bls.SecretKey)
	err = sec.SetDecString(cred.signing_sk.Text(10))
	if err != nil {
		return nil, err
	}
	sig := sec.SignByte(messageToSign[:])

	// deposit data
	depositData := new(DepositData)
	depositData.Amount = depositMessage.Amount
	copy(depositData.WithdrawalCredentials[:], depositMessage.WithdrawalCredentials)
	copy(depositData.Pubkey[:], depositMessage.Pubkey)
	copy(depositData.Signature[:], sig.Serialize())

	return depositData, nil
}

func (cred *Credential) WithdrawCredentials() ([]byte, error) {
	var withdrawal_credentials []byte
	withdrawType, err := cred.withdrawType()
	if err != nil {
		return nil, err
	}

	if withdrawType == BLS_WITHDRAWAL {
		withdrawal_credentials = append(withdrawal_credentials, BLS_WITHDRAWAL_PREFIX)
		pub, err := cred.WithdrawalPK()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(pub)
		withdrawal_credentials = append(withdrawal_credentials, sum[1:]...)
	} else if withdrawType == ETH1_ADDRESS_WITHDRAWAL && cred.eth1_withdrawal_address != nil {
		withdrawal_credentials = append(withdrawal_credentials, ETH1_ADDRESS_WITHDRAWAL_PREFIX)
		withdrawal_credentials = append(withdrawal_credentials, make([]byte, 11)...)
		withdrawal_credentials = append(withdrawal_credentials, cred.eth1_withdrawal_address...)
	} else {
		return nil, ErrorWithdrawType
	}

	return withdrawal_credentials, nil
}
