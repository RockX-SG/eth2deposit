package eth2deposit

import "encoding/binary"

type BaseChainSetting struct {
	ETH2_NETWORK_NAME    string
	GENESIS_FORK_VERSION [4]byte
}

const DEPOSIT_CLI_VERSION = "2.8.0"

const (
	purpose   = "12381"
	coin_type = "3600"
)

const (
	MAINNET = "mainnet"
	PYRMONT = "pyrmont"
	PRATER  = "prater"
	HOLESKY = "holesky"
	HOODI   = "hoodi"
)

var (
	MainnetSetting BaseChainSetting
	PyrmontSetting BaseChainSetting
	PraterSetting  BaseChainSetting
	HoleskySetting BaseChainSetting
	HoodiSetting   BaseChainSetting
)

func init() {
	// Eth2 Mainnet setting
	MainnetSetting.ETH2_NETWORK_NAME = MAINNET
	binary.BigEndian.PutUint32(MainnetSetting.GENESIS_FORK_VERSION[:], 0x00000000)

	// Eth2 pre-launch testnet (spec v1.0.0)
	PyrmontSetting.ETH2_NETWORK_NAME = PYRMONT
	binary.BigEndian.PutUint32(PyrmontSetting.GENESIS_FORK_VERSION[:], 0x00002009)
	// Eth2 testnet (spec v1.0.1)
	PraterSetting.ETH2_NETWORK_NAME = PRATER
	binary.BigEndian.PutUint32(PraterSetting.GENESIS_FORK_VERSION[:], 0x00001020)

	// Holesky setting
	HoleskySetting.ETH2_NETWORK_NAME = HOLESKY
	binary.BigEndian.PutUint32(HoleskySetting.GENESIS_FORK_VERSION[:], 0x01017000)

	// Hoodi setting
	HoodiSetting.ETH2_NETWORK_NAME = HOODI
	binary.BigEndian.PutUint32(HoodiSetting.GENESIS_FORK_VERSION[:], 0x10000910)
}
