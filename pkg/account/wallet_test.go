package account

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
Scenario: Create wallet
	Given an IRIS key
	When I want create a wallet
	Then I get the generated wallet with the IRIS service enable with the provided private key
*/
func TestCreateWallet(t *testing.T) {
	w := NewWallet("iriskey")
	assert.NotNil(t, w)
	assert.NotEmpty(t, w.Services)
	assert.Equal(t, "iriskey", w.Services["IRIS"].PrivateKey)
}
