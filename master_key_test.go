package eth2deposit

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMasterKey(t *testing.T) {
	account, _ := new(big.Int).SetString("0x0ce20f2274F4260eFC0D3FD4d736581C403d52Ba", 0)
	var masterKey [32]byte
	copy(masterKey[:], account.Bytes())
	master := NewMasterKey(masterKey)
	assert.NotNil(t, master)

	for i := 0; i < 128; i++ {
		buf, err := master.DeriveChild(uint64(i))
		assert.Nil(t, err)
		t.Log("child", i, hex.EncodeToString(buf.Bytes()))
		buf.Destroy()
	}
}
