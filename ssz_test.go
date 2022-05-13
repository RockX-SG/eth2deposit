package eth2deposit

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestComputeDepositForkDataRoot(t *testing.T) {
	var (
		in       = [4]byte{0x12, 0x12, 0x12, 0x12}
		expected = []byte("\rf`\x8a\xf5W\xf4\xfa\xdb\xfc\xe2H\xac7\xf6\xe7c\x9c\xe3q\x10\x0cC\xd1Z\xad\x05\xcb\x08\xac\x1d\xc2")
	)
	out, err := ComputeDepositForkDataRoot(in)
	assert.Nil(t, err)
	assert.Equal(t, expected, out)
}

func TestComputeDepositDomain(t *testing.T) {
	var (
		in       = [4]byte{0x12, 0x12, 0x12, 0x12}
		expected = []byte("\x03\x00\x00\x00\rf`\x8a\xf5W\xf4\xfa\xdb\xfc\xe2H\xac7\xf6\xe7c\x9c\xe3q\x10\x0cC\xd1Z\xad\x05\xcb")
	)

	out, err := ComputeDepositDomain(in)
	assert.Nil(t, err)
	assert.Equal(t, expected, out)
}

func TestComputeSigningRoot(t *testing.T) {
	var (
		in = DepositMessage{
			Pubkey:                [48]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12},
			WithdrawalCredentials: [32]byte{0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12},
			Amount:                100,
		}
		expected = []byte("g\xa33\x0f\xf8{\xdbF\xbb{\x80\xcazd\x1e9\x8dj\xc4\xe8zhVR|\xac\xc8)\xfba\x89o")
	)
	getDomain := func(length int) []byte {
		var out []byte
		for i := 0; i < length; i++ {
			out = append(out, 0x12)
		}
		return out
	}
	t.Run("len(domain)=32", func(t *testing.T) {
		domain := getDomain(32)
		out, err := ComputeSigningRoot(&in, domain)
		assert.Nil(t, err)
		assert.Equal(t, expected, out)
	})
	t.Run("len(domain)=31", func(t *testing.T) {
		domain := getDomain(31)
		out, err := ComputeSigningRoot(&in, domain)
		assert.Nil(t, out)
		assert.NotNil(t, err)
	})
	t.Run("len(domain)=33", func(t *testing.T) {
		domain := getDomain(33)
		out, err := ComputeSigningRoot(&in, domain)
		assert.Nil(t, out)
		assert.NotNil(t, err)
	})
}
