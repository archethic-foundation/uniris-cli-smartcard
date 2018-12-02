package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uniris/uniris-cli/pkg/account"
)

/*
Scenario: Hash the wallets
	Given a wallet
	When I want to hash it
	Then I get the same hash every time
*/
func TestHashWallet(t *testing.T) {

	h := NewHasher()
	w := account.NewWallet("irisKey")

	hash, err := h.HashWallet(w)
	assert.Nil(t, err)
	assert.NotEmpty(t, hash)

	wB, _ := json.Marshal(w)
	assert.NotEqual(t, wB, hash)

	hash2, err := h.HashWallet(w)
	assert.Nil(t, err)
	assert.Equal(t, hash, hash2)
}
