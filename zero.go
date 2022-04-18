package eth2deposit

import "math/big"

// wipeBig wipes big int
func wipeBig(x *big.Int) {
	b := x.Bits()
	for i := range b {
		b[i] = 0
	}
	x.SetInt64(0)
}

// wipeSlice wipes byte slice
func wipeSlice(x []byte) {
	for i := range x {
		x[i] = 0
	}
}
