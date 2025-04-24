package eth2deposit

import (
	"fmt"
	"github.com/herumi/bls-eth-go-binary/bls"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

type CompactDepositData struct {
	PubKey             string `json:"pubkey"`
	WithdrawCredential string `json:"withdrawal_credentials"`
	Amount             int    `json:"amount"`
	Signature          string `json:"signature"`
	DepositMessageRoot string `json:"deposit_message_root"`
	DepositDataRoot    string `json:"deposit_data_root"`
	ForkVersion        string `json:"fork_version"`
	Eth2NetworkName    string `json:"network_name"`
	DepositCliVersion  string `json:"deposit_cli_version"`
}

func init() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
}

func _path_to_nodes(path string) ([]uint32, error) {
	path = strings.ReplaceAll(path, " ", "")

	matched, err := regexp.MatchString("[m1234567890/]", path)
	if err != nil {
		return nil, err
	}

	if !matched {
		return nil, fmt.Errorf("Invalid path:%v", path)
	}

	indices := strings.Split(path, "/")
	if indices[0] != "m" {
		return nil, fmt.Errorf("The first character of path should be `m`. Got %v", indices[0])
	}

	var indicesList []uint32
	for i := 1; i < len(indices); i++ {
		d, err := strconv.ParseUint(indices[i], 10, 32)
		if err != nil {
			return nil, err
		}

		indicesList = append(indicesList, uint32(d))
	}

	return indicesList, nil
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

	nodes, err := _path_to_nodes(path)
	if err != nil {
		return nil, err
	}

	for k := range nodes {
		sk, err = _derive_child_SK(sk, nodes[k])
		if err != nil {
			return nil, err
		}
	}
	return sk, nil
}
