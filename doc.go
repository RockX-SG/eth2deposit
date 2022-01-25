// Copyright rockx.com
// All rights reserved

/*
This package aims to enhance online staking service procedure
with safe usage of master key to derive child keys

    package main

    import (
    	"crypto/rand"
    	"fmt"
    	"io"

    	"github.com/RockX-SG/eth2deposit"
    	"github.com/awnumar/memguard"
    )

    func main() {
    	// Safely terminate in case of an interrupt signal
    	memguard.CatchInterrupt()
    	// Purge the session when we return
    	defer memguard.Purge()

    	var seed [32]byte
    	io.ReadFull(rand.Reader, seed[:])

    	// create master key and dervie 100th child key
    	masterKey := eth2deposit.NewMasterKey(seed)
    	lockedBuffer, err := masterKey.DeriveChild(100)
    	if err != nil {
    		panic(err)
    	}

    	// create a deposit credential
    	cred, err := eth2deposit.NewCredential(lockedBuffer, 0, nil, eth2deposit.MainnetSetting)
    	if err != nil {
    		panic(err)
    	}

    	bts, err := cred.MarshalText()
    	if err != nil {
    		panic(err)
    	}

    	fmt.Println(string(bts))
    }

*/
package eth2deposit
