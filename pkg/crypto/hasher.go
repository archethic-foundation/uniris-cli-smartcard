package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/uniris/uniris-cli/pkg/account"
)

//Hasher defines methods for hashing
type Hasher interface {
	account.Hasher
}

type hasher struct{}

//NewHasher implements an hasher for the enrollment
func NewHasher() Hasher {
	return hasher{}
}

func hashString(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

func (h hasher) HashWallet(wallet account.Wallet) (string, error) {
	b, err := json.Marshal(wallet)
	if err != nil {
		return "", err
	}

	return hashString(string(b)), nil
}

func (h hasher) HashString(str string) string {
	return hashString(str)
}
