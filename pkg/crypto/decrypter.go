package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"

	"github.com/uniris/uniris-cli/pkg/account"

	"github.com/uniris/ecies/pkg"
)

//Decrypter defines methods for decryption
type Decrypter interface {
	account.Decrypter
}

type decrypter struct{}

//NewDecrypter creates a new decrypter
func NewDecrypter() Decrypter {
	return decrypter{}
}

func (d decrypter) DecryptWallet(encWallet string, aesKey string) (w account.Wallet, err error) {
	decodedKey, err := hex.DecodeString(aesKey)
	if err != nil {
		return
	}

	c, err := aes.NewCipher(decodedKey)
	if err != nil {
		return
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return
	}
	nonceSize := gcm.NonceSize()

	decodeWallet, err := hex.DecodeString(encWallet)
	if err != nil {
		return
	}

	nonce, ciphertext := decodeWallet[:nonceSize], decodeWallet[nonceSize:]
	clearWallet, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return
	}

	if err = json.Unmarshal(clearWallet, &w); err != nil {
		return
	}
	return
}

func (d decrypter) DecryptString(str string, pvKey string) (string, error) {
	return decryptECIES(str, pvKey)
}

func decryptECIES(hexData string, pvKey string) (string, error) {
	decodedKey, err := hex.DecodeString(pvKey)
	if err != nil {
		return "", err
	}

	key, err := x509.ParseECPrivateKey(decodedKey)
	if err != nil {
		return "", err
	}

	decodedData, err := hex.DecodeString(hexData)
	if err != nil {
		return "", err
	}

	clearData, err := ecies.ImportECDSA(key).Decrypt(decodedData, nil, nil)
	if err != nil {
		return "", err
	}

	return string(clearData), nil
}
