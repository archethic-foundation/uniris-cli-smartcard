package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/uniris/ecies/pkg"
	"github.com/uniris/uniris-cli/pkg/account"
)

//Encrypter defines methods for encryption
type Encrypter interface {
	account.Encrypter
}

type encrypter struct{}

//NewEncrypter implements an encrypted
func NewEncrypter() Encrypter {
	return encrypter{}
}

func (e encrypter) EncryptString(str string, pubKey string) (string, error) {
	return e.encryptECIES(str, pubKey)
}

func (e encrypter) EncryptWallet(w account.Wallet, aesKey string) (string, error) {
	wB, err := json.Marshal(w)
	if err != nil {
		return "", err
	}

	decodedKey, err := hex.DecodeString(aesKey)
	if err != nil {
		return "", err
	}

	c, err := aes.NewCipher(decodedKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipher := gcm.Seal(nonce, nonce, wB, nil)

	return hex.EncodeToString(cipher), nil
}

func (e encrypter) EncryptID(id account.ID, robotPubKey string) (string, error) {
	b, err := json.Marshal(id)
	if err != nil {
		return "", err
	}

	return e.encryptECIES(string(b), robotPubKey)
}

func (e encrypter) EncryptKeychain(kc account.Keychain, robotPubKey string) (string, error) {
	b, err := json.Marshal(kc)
	if err != nil {
		return "", err
	}

	return e.encryptECIES(string(b), robotPubKey)
}

func (e encrypter) encryptECIES(data string, pbKey string) (string, error) {
	decodeKey, err := hex.DecodeString(string(pbKey))
	if err != nil {
		return "", err
	}

	key, err := x509.ParsePKIXPublicKey(decodeKey)
	if err != nil {
		return "", err
	}

	eciesKey := ecies.ImportECDSAPublic(key.(*ecdsa.PublicKey))
	cipher, err := ecies.Encrypt(rand.Reader, eciesKey, []byte(data), nil, nil)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(cipher), nil
}
