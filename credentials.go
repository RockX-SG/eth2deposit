package main

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
)

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
	withdrawal_sk *big.Int
	signing_sk    *big.Int
}

func NewCredential(seed *big.Int, account uint32) (*Credential, error) {
	cred := new(Credential)
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

func (cred *Credential) SkToPk(s *bn256.Suite, pt kyber.Point) ([]byte, error) {
	//POW_2_283 := big.NewInt(0).Lsh(283)
	//POW_2_382 := big.NewInt(0).Lsh(382)
	//bts, err := pt.MarshalBinary()
	//if err != nil {
	//		return nil, err
	//	}
	//elliptic.Unmarshal(
	return nil, nil
}

func (cred *Credential) SigningPK() (pk kyber.Point) {
	s := bn256.NewSuiteG2()
	priv := s.Scalar().SetBytes(cred.signing_sk.Bytes())
	pub := s.Point().Mul(priv, nil)
	return pub
}
