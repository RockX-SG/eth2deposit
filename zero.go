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
