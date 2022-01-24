package eth2deposit

type SigningData struct {
	ObjectRoot [32]byte `json:"current_version" ssz-size:"32"`
	Domain     [32]byte `json:"domain" ssz-size:"32"`
}

type ForkData struct {
	CurrentVersion       [4]byte  `json:"current_version" ssz-size:"4"`
	GenesisValidatorRoot [32]byte `json:"genesis_validators_root" ssz-size:"32"`
}

type DepositMessage struct {
	Pubkey                [48]byte `json:"pubkey" ssz-size:"48"`
	WithdrawalCredentials [32]byte `json:"withdrawal_credentials" ssz-size:"32"`
	Amount                uint64   `json:"amount"`
}
type DepositData struct {
	Pubkey                [48]byte `json:"pubkey" ssz-size:"48"`
	WithdrawalCredentials [32]byte `json:"withdrawal_credentials" ssz-size:"32"`
	Amount                uint64   `json:"amount"`
	Signature             [96]byte `json:"signature" ssz-size:"96"`
	Root                  [32]byte `ssz:"-"`
}
