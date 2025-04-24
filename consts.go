package eth2deposit

import (
	"errors"
)

var (
	blsWithdrawalPrefix                 = byte(0x00)
	eth1AddressWithdrawalPrefix         = byte(0x01)
	eth1AddressWithdrawalCompoundPrefix = byte(0x02)
)

type WithdrawType int

const (
	invalidWithdrawal             = WithdrawType(-1)
	blsWithdrawal                 = 0
	eth1AddressWithdrawal         = 1
	eth1AddressWithdrawalCompound = 2
)

var (
	errorWithdrawPrefix = errors.New("Invalid withdrawal_prefix")
	errorWithdrawType   = errors.New("Invalid withdrawal_type")
)

var (
	domainDeposit [4]byte = [4]byte{0x03, 0x00, 0x00, 0x00}
	zeroBytes32   [32]byte
)
