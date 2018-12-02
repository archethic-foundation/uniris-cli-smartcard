package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	uniris "github.com/uniris/uniris-cli/pkg"
	"github.com/uniris/uniris-cli/pkg/account"
	"golang.org/x/crypto/pbkdf2"
)

//KeyGenerator defines methods for key generation
type KeyGenerator interface {
	account.KeyGenerator
}

type keyGenerator struct {
}

//NewKeyGenerator implements a key generator
func NewKeyGenerator() KeyGenerator {
	return keyGenerator{}
}

func (e keyGenerator) NewAESKey(secret string) (string, error) {
	hash := sha256.New

	//Generate salt
	salt := make([]byte, hash().Size())
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return "", err
	}

	//Generate a key from the salt and the secret
	derivedKey := pbkdf2.Key([]byte(secret), salt, 100000, 16, hash)
	return hex.EncodeToString(derivedKey), nil
}

func (e keyGenerator) NewKeyPair(secret string) (kp uniris.KeyPair, err error) {
	var reader io.Reader
	if len(secret) == 0 {
		reader = rand.Reader
	} else {
		lengthOfKey := elliptic.P256().Params().BitSize
		secretBytes := make([]byte, lengthOfKey)
		bStr, _ := ioutil.ReadAll(bytes.NewBufferString(secret))
		if len(bStr) > lengthOfKey {
			err = errors.New("Invalid secret size")
			return
		}
		for i, b := range bStr {
			secretBytes[i] = b
		}
		reader = bytes.NewReader(secretBytes)
	}

	pvKey, err := ecdsa.GenerateKey(elliptic.P256(), reader)
	if err != nil {
		return
	}

	pvDER, err := x509.MarshalECPrivateKey(pvKey)
	if err != nil {
		return
	}

	pbDER, err := x509.MarshalPKIXPublicKey(pvKey.Public())
	if err != nil {
		return
	}

	return uniris.KeyPair{
		PrivateKey: fmt.Sprintf("%x", pvDER),
		PublicKey:  fmt.Sprintf("%x", pbDER),
	}, nil
}
