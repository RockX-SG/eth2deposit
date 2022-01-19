package main

import (
	"errors"
)

var (
	BLS_WITHDRAWAL_PREFIX          = byte(0x00)
	ETH1_ADDRESS_WITHDRAWAL_PREFIX = byte(0x01)
)

type WithdrawType int

const (
	INVALID_WITHDRAW        = WithdrawType(-1)
	BLS_WITHDRAWAL          = 0
	ETH1_ADDRESS_WITHDRAWAL = 1
)

var (
	ErrorWithdrawPrefix = errors.New("Invalid withdrawal_prefix")
	ErrorWithdrawType   = errors.New("Invalid withdrawal_type")
)

var (
	DOMAIN_DEPOSIT [4]byte = [4]byte{0x03, 0x00, 0x00, 0x00}
	ZERO_BYTES32   [32]byte
)
