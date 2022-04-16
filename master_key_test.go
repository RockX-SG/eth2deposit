package eth2deposit

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMasterKey(t *testing.T) {
	account, _ := new(big.Int).SetString("0x0ce21f2374F4568eFC0D3FD4d736581C403d52Ba", 0)
	var masterKey [32]byte
	copy(masterKey[:], account.Bytes())
	master := NewMasterKey(masterKey)
	assert.NotNil(t, master)

	for i := 0; i < 128; i++ {
		buf, err := master.DeriveChild(fmt.Sprintf("m/%v", i))
		assert.Nil(t, err)
		t.Log("child", i, hex.EncodeToString(buf.Bytes()))

		cred, err := NewCredential(buf, 0, nil, MainnetSetting)
		assert.Nil(t, err)
		text, err := cred.MarshalText()
		assert.Nil(t, err)
		t.Log("mainnet:", string(text))

		buf, err = master.DeriveChild(fmt.Sprintf("m/%v", i))
		assert.Nil(t, err)
		cred, err = NewCredential(buf, 0, nil, PyrmontSetting)
		assert.Nil(t, err)
		text, err = cred.MarshalText()
		assert.Nil(t, err)
		t.Log("pyrmont:", string(text))

		buf.Destroy()
	}
}
