package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uniris/uniris-cli/pkg/account"
)

/*
Scenario: Decrypt an encrypted wallet
	Given a cipher wallet and an AES key
	When I want to decrypt the wallet
	Then I get the clear wallet
*/
func TestDecryptEncryptedWallet(t *testing.T) {

	w := account.NewWallet(fmt.Sprintf("%x", "key iris"))

	k := NewKeyGenerator()
	secret := "my key"
	aesKey, _ := k.NewAESKey(secret)

	enc := NewEncrypter()
	cipherWallet, _ := enc.EncryptWallet(w, fmt.Sprintf("%x", aesKey))

	d := NewDecrypter()

	clearW, err := d.DecryptWallet(
		cipherWallet,
		fmt.Sprintf("%x", aesKey))

	assert.Nil(t, err)
	assert.Equal(t, w, clearW)
}

/*
Scenario: Decrypt an encrypted string
	Given an encrypted string and a public key
	When I want to decrypt cipher text
	Then I get the clear string
*/
func TestDecryptString(t *testing.T) {

	clear := "clear text"
	keys, _ := NewKeyGenerator().NewKeyPair("")

	e := NewEncrypter()
	cipher, _ := e.EncryptString(clear, keys.PublicKey)

	d := NewDecrypter()

	decipher, err := d.DecryptString(cipher, keys.PrivateKey)
	assert.Nil(t, err)
	assert.Equal(t, clear, decipher)
}
