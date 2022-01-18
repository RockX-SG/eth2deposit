package main

import "errors"

var (
	BLS_WITHDRAWAL_PREFIX          = byte(0)
	ETH1_ADDRESS_WITHDRAWAL_PREFIX = byte(1)
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
