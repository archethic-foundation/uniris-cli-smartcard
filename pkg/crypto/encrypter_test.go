package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/uniris/uniris-cli/pkg/account"

	"github.com/uniris/ecies/pkg"

	"github.com/stretchr/testify/assert"
)

/*
Scenario: Encrypt string
	Given a string
	When I want encrypt it with ECIES
	Then I get the string encrypted and I can decrypt with my ECDSA private key
*/
func TestEncryptString(t *testing.T) {

	e := encrypter{}

	superKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pbKey, _ := x509.MarshalPKIXPublicKey(superKey.Public())

	cipherKey, err := e.EncryptString("my key", hex.EncodeToString(pbKey))
	assert.Nil(t, err)
	assert.NotEmpty(t, cipherKey)

	decodeCipherKey, _ := hex.DecodeString(cipherKey)

	clearKey, _ := ecies.ImportECDSA(superKey).Decrypt(decodeCipherKey, nil, nil)
	assert.Equal(t, "my key", string(clearKey))
}

/*
Scenario: Encrypt a wallet
	Given the wallet and a public key
	When I want encrypt it with my AES key
	Then I get the wallet encrypted and I can decrypt it with my AES key
*/
func TestEncryptWallet(t *testing.T) {
	e := encrypter{}

	w := account.NewWallet("keyIRIS")

	cipherKey := make([]byte, sha256.New().Size())
	_, err := io.ReadFull(rand.Reader, cipherKey)

	cipherWallet, err := e.EncryptWallet(w, fmt.Sprintf("%x", cipherKey))
	assert.Nil(t, err)
	assert.NotEmpty(t, cipherWallet)

	decodeCipher, _ := hex.DecodeString(cipherWallet)

	c, _ := aes.NewCipher(cipherKey)
	gcm, _ := cipher.NewGCM(c)
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := decodeCipher[:nonceSize], decodeCipher[nonceSize:]
	clearWallet, err := gcm.Open(nil, nonce, ciphertext, nil)
	assert.Nil(t, err)
	assert.NotEmpty(t, clearWallet)

	assert.Equal(t, fmt.Sprintf(`{"services":{"IRIS":{"privk":"%s"}}}`, "keyIRIS"), string(clearWallet))

}

/*
Scenario: Encrypt ID data
	Given an account ID, a shared robot public key
	When I want encrypt it with ECIES
	Then I get all the values of encrypted
*/
func TestEncryptID(t *testing.T) {
	e := encrypter{}

	data := account.ID{
		PublicKey:            "public key",
		EncryptedAESKey:      "encaeskey",
		EncryptedAddrByID:    "encaddrperson",
		EncryptedAddrByRobot: "encaddrrobot",
		Hash:                 "hash",
	}

	robotMasterKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	robotPv, _ := x509.MarshalECPrivateKey(robotMasterKey)
	robotPub, _ := x509.MarshalPKIXPublicKey(robotMasterKey.Public())

	cipher, err := e.EncryptID(data, hex.EncodeToString(robotPub))
	assert.Nil(t, err)
	assert.NotNil(t, cipher)
	assert.NotEmpty(t, cipher)

	clearText, _ := decryptECIES(cipher, hex.EncodeToString(robotPv))
	assert.NotEmpty(t, clearText)

	var id account.ID
	json.Unmarshal([]byte(clearText), &id)

	assert.Equal(t, "hash", id.Hash)
}

/*
Scenario: Encrypt keychain data
	Given an account keychain, a shared robot public key
	When I want encrypt it with ECIES
	Then I get all the values of encrypted
*/
func TestEncryptKeychain(t *testing.T) {
	e := encrypter{}

	data := account.Keychain{
		EncryptedAddrByRobot: "encaddrrobot",
		EncryptedWallet:      "enc wallet",
		IDPublicKey:          "public key",
	}

	robotMasterKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	robotPv, _ := x509.MarshalECPrivateKey(robotMasterKey)
	robotPub, _ := x509.MarshalPKIXPublicKey(robotMasterKey.Public())

	cipher, err := e.EncryptKeychain(data, hex.EncodeToString(robotPub))
	assert.Nil(t, err)
	assert.NotNil(t, cipher)
	assert.NotEmpty(t, cipher)

	clearText, _ := decryptECIES(cipher, hex.EncodeToString(robotPv))
	assert.NotEmpty(t, clearText)

	var kc account.Keychain
	json.Unmarshal([]byte(clearText), &kc)

	assert.Equal(t, "enc wallet", kc.EncryptedWallet)
}
