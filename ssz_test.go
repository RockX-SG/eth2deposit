package eth2deposit

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeDepositForkDataRoot(t *testing.T) {
	data, err := compute_deposit_fork_data_root(MainnetSetting.GENESIS_FORK_VERSION)
	assert.Nil(t, err)
	t.Log(hex.EncodeToString(data))

}

func TestComputeDepositDomain(t *testing.T) {
	data, err := compute_deposit_domain(MainnetSetting.GENESIS_FORK_VERSION)
	assert.Nil(t, err)
	t.Log(hex.EncodeToString(data))
}
