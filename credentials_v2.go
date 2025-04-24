package eth2deposit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/awnumar/memguard"
	"github.com/herumi/bls-eth-go-binary/bls"
	"math/big"
)

// Credential defines a ETH2 bls signing credential
type CredentialV2 struct {
	chain                   BaseChainSetting
	eth1_withdrawal_address []byte
	withdrawal_sk           *memguard.Enclave // stores based-10 string of seed key
	signing_sk              *memguard.Enclave // stores based-10 string of seed key
	amount                  uint64
}

// NewCredential creates an ETH2 BLS signing credential
func NewCredentialV2(buf *memguard.LockedBuffer, account uint32, hex_eth1_withdrawal_address []byte, chain BaseChainSetting, amount uint64) (*CredentialV2, error) {
	seed := new(big.Int).SetBytes(buf.Bytes())
	defer buf.Destroy()

	cred := new(CredentialV2)
	cred.chain = chain
	cred.eth1_withdrawal_address = hex_eth1_withdrawal_address
	cred.amount = amount
	withdrawal_key_path := fmt.Sprintf("m/%v/%v/%d/0", purpose, coin_type, account)
	withdrawal_sk, err := _seed_and_path_to_key(seed, withdrawal_key_path)
	if err != nil {
		return nil, err
	}
	cred.withdrawal_sk = memguard.NewEnclave([]byte(withdrawal_sk.String()))

	signing_key_path := fmt.Sprintf("%s/0", withdrawal_key_path)
	signing_sk, err := _seed_and_path_to_key(seed, signing_key_path)
	if err != nil {
		return nil, err
	}
	cred.signing_sk = memguard.NewEnclave([]byte(signing_sk.String()))

	return cred, nil
}

func (cred *CredentialV2) withdrawPrefix() byte {
	if cred.eth1_withdrawal_address != nil {
		return eth1AddressWithdrawalCompoundPrefix
	}
	return blsWithdrawalPrefix
}

func (cred *CredentialV2) withdrawType() (WithdrawType, error) {
	prefix := cred.withdrawPrefix()
	if prefix == blsWithdrawalPrefix {
		return blsWithdrawal, nil
	} else if prefix == eth1AddressWithdrawalCompoundPrefix {
		return eth1AddressWithdrawalCompound, nil
	}
	return invalidWithdrawal, errorWithdrawPrefix
}

/*******************************************************************************
 *
 * Public methods for credential
 *
 *******************************************************************************/

// String returns json string compatible with eth2deposit
func (cred *CredentialV2) MarshalText() ([]byte, error) {
	msg := new(CompactDepositData)
	withdraw_credential, err := cred.WithdrawCredentials()
	if err != nil {
		return nil, err
	}
	signed_deposit, err := cred.SignedDeposit()
	if err != nil {
		return nil, err
	}
	signed_deposit_root, err := signed_deposit.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	pubkey, err := cred.SigningPK()
	if err != nil {
		return nil, err
	}
	deposit_message, err := cred.DepositMessage()
	if err != nil {
		return nil, err
	}

	deposit_message_root, err := deposit_message.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	msg.PubKey = hex.EncodeToString(pubkey)
	msg.WithdrawCredential = hex.EncodeToString(withdraw_credential)
	msg.Amount = int(cred.amount * 1e9)
	msg.Signature = hex.EncodeToString(signed_deposit.Signature[:])
	msg.DepositMessageRoot = hex.EncodeToString(deposit_message_root[:])
	msg.DepositDataRoot = hex.EncodeToString(signed_deposit_root[:])
	msg.ForkVersion = hex.EncodeToString(cred.chain.GENESIS_FORK_VERSION[:])
	msg.Eth2NetworkName = cred.chain.ETH2_NETWORK_NAME
	msg.DepositCliVersion = DEPOSIT_CLI_VERSION

	return json.Marshal([]*CompactDepositData{msg})
}

// WithdrawalSK returns locked withdraw secret key in 10-based string
func (cred *CredentialV2) WithdrawalSK() (*memguard.LockedBuffer, error) {
	return cred.withdrawal_sk.Open()
}

// SigningSK returns locked signing secret key in 10-based string
func (cred *CredentialV2) SigningSK() (*memguard.LockedBuffer, error) {
	return cred.signing_sk.Open()
}

// DepositMessage retrieves deposit message
func (cred *CredentialV2) DepositMessage() (*DepositMessage, error) {
	msg := new(DepositMessage)
	pubkey, err := cred.SigningPK()
	if err != nil {
		return nil, err
	}

	withdrawCredential, err := cred.WithdrawCredentials()
	if err != nil {
		return nil, err
	}

	copy(msg.Pubkey[:], pubkey)
	copy(msg.WithdrawalCredentials[:], withdrawCredential)
	msg.Amount = 1e9 * cred.amount

	return msg, nil
}

// SigningPK returns public key of BLS signing account
func (cred *CredentialV2) SigningPK() (pub []byte, err error) {
	sec := new(bls.SecretKey)
	buf, err := cred.signing_sk.Open()
	defer buf.Destroy()

	err = sec.SetDecString(buf.String())
	if err != nil {
		return nil, err
	}

	return sec.GetPublicKey().Serialize(), nil
}

// WithdrawalPK returns public key of BLS withdrawal account
func (cred *CredentialV2) WithdrawalPK() (pub []byte, err error) {
	buf, err := cred.withdrawal_sk.Open()
	defer buf.Destroy()

	sec := new(bls.SecretKey)
	err = sec.SetDecString(buf.String())
	if err != nil {
		return nil, err
	}

	return sec.GetPublicKey().Serialize(), nil
}

// SignedDeposit returns the deposit data
func (cred *CredentialV2) SignedDeposit() (*DepositData, error) {
	// deposit message
	depositMessage, err := cred.DepositMessage()

	// deposit domain
	domain, err := ComputeDepositDomain(cred.chain.GENESIS_FORK_VERSION)
	if err != nil {
		return nil, err
	}

	// sign
	messageToSign, err := ComputeSigningRoot(depositMessage, domain)
	if err != nil {
		return nil, err
	}

	// open encalve
	sec := new(bls.SecretKey)
	buf, err := cred.signing_sk.Open()
	if err != nil {
		return nil, err
	}
	defer buf.Destroy()

	// sign
	err = sec.SetDecString(buf.String())
	if err != nil {
		return nil, err
	}
	sig := sec.SignByte(messageToSign[:])

	// deposit data
	depositData := new(DepositData)
	depositData.Amount = depositMessage.Amount
	depositData.WithdrawalCredentials = depositMessage.WithdrawalCredentials
	depositData.Pubkey = depositMessage.Pubkey
	copy(depositData.Signature[:], sig.Serialize())

	return depositData, nil
}

// WithdrawCredentials returns credential bytes
func (cred *CredentialV2) WithdrawCredentials() ([]byte, error) {
	var withdrawal_credentials []byte
	withdrawType, err := cred.withdrawType()
	if err != nil {
		return nil, err
	}

	if withdrawType == blsWithdrawal {
		withdrawal_credentials = append(withdrawal_credentials, blsWithdrawalPrefix)
		pub, err := cred.WithdrawalPK()
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(pub)
		withdrawal_credentials = append(withdrawal_credentials, sum[1:]...)
	} else if withdrawType == eth1AddressWithdrawalCompound && cred.eth1_withdrawal_address != nil {
		withdrawal_credentials = append(withdrawal_credentials, eth1AddressWithdrawalCompoundPrefix)
		withdrawal_credentials = append(withdrawal_credentials, make([]byte, 11)...)
		withdrawal_credentials = append(withdrawal_credentials, cred.eth1_withdrawal_address...)
	} else {
		return nil, errorWithdrawType
	}

	return withdrawal_credentials, nil
}
