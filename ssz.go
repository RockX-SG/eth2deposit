package eth2deposit

import (
	"errors"
	"fmt"
	ssz "github.com/ferranbt/fastssz"
)

func ComputeDepositDomain(fork_version [4]byte) ([]byte, error) {
	domain_type := domainDeposit
	fork_data_root, err := ComputeDepositForkDataRoot(fork_version)
	if err != nil {
		return nil, err
	}

	return append(domain_type[:], fork_data_root[:28]...), nil
}

func ComputeDepositForkDataRoot(current_version [4]byte) ([]byte, error) {
	forkData := new(ForkData)
	forkData.CurrentVersion = current_version
	forkData.GenesisValidatorRoot = zeroBytes32

	err := forkData.HashTreeRootWith(ssz.DefaultHasherPool.Get())
	if err != nil {
		return nil, err
	}
	root, err := forkData.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	return root[:], nil
}

func ComputeSigningRoot(ssz_object ssz.HashRoot, domain []byte) ([]byte, error) {
	if len(domain) != 32 {
		return nil, errors.New(fmt.Sprintf("Domain should be in 32 bytes. Got %v.", len(domain)))
	}
	signingRoot := new(SigningData)
	copy(signingRoot.Domain[:], domain)
	objectRoot, err := ssz_object.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	signingRoot.ObjectRoot = objectRoot

	messageToSign, err := signingRoot.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	return messageToSign[:], nil
}

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
