package eth2deposit

import "encoding/binary"

type BaseChainSetting struct {
	ETH2_NETWORK_NAME    string
	GENESIS_FORK_VERSION [4]byte
}

const (
	purpose   = "12381"
	coin_type = "3600"
)

const (
	MAINNET = "mainnet"
	PYRMONT = "pyrmont"
	PRATER  = "prater"
)

var (
	MainnetSetting BaseChainSetting
	PyrmontSetting BaseChainSetting
	PraterSetting  BaseChainSetting
)

func init() {
	// Eth2 Mainnet setting
	MainnetSetting.ETH2_NETWORK_NAME = MAINNET
	binary.BigEndian.PutUint32(MainnetSetting.GENESIS_FORK_VERSION[:], 0x00000000)

	// Eth2 pre-launch testnet (spec v1.0.0)
	PyrmontSetting.ETH2_NETWORK_NAME = PYRMONT
	binary.BigEndian.PutUint32(PyrmontSetting.GENESIS_FORK_VERSION[:], 0x00002009)
	// Eth2 testnet (spec v1.0.1)
	PyrmontSetting.ETH2_NETWORK_NAME = PRATER
	binary.BigEndian.PutUint32(PraterSetting.GENESIS_FORK_VERSION[:], 0x00001020)
}
