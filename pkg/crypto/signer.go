package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/uniris/uniris-cli/pkg/account"
)

//Signer defines methods for signing
type Signer interface {
	account.Signer
}

type signer struct {
}

type ecdsaSignature struct {
	R, S *big.Int
}

//NewSigner implements signer for the enrollment
func NewSigner() Signer {
	return signer{}
}

func (signer signer) SignString(str string, pvKey string) (string, error) {
	return sign(str, pvKey)
}

func (signer signer) SignID(id *account.ID, emPvKey, idPvKey string) error {
	json, err := json.Marshal(id)
	if err != nil {
		return err
	}

	emSig, err := sign(string(json), emPvKey)
	if err != nil {
		return err
	}

	id.EmitterSignature = emSig

	idSig, err := sign(string(json), idPvKey)
	if err != nil {
		return err
	}
	id.IDSignature = idSig

	return nil
}

func (signer signer) SignKeychain(kc *account.Keychain, emPvKey, idPvKey string) error {
	json, err := json.Marshal(kc)
	if err != nil {
		return err
	}

	emSig, err := sign(string(json), emPvKey)
	if err != nil {
		return err
	}

	kc.EmitterSignature = emSig

	idSig, err := sign(string(json), idPvKey)
	if err != nil {
		return err
	}
	kc.IDSignature = idSig

	return nil
}

func (signer signer) SignCreationRequest(req *account.CreationRequest, pvKey string) error {
	json, err := json.Marshal(req)
	if err != nil {
		return err
	}

	sig, err := sign(string(json), pvKey)
	if err != nil {
		return err
	}
	req.Signature = sig
	return nil
}

func (signer signer) VerifyCreationResultSignature(res account.CreationResult, robotPbKey string) error {
	b, err := json.Marshal(account.CreationResult{
		Transactions: res.Transactions,
	})
	if err != nil {
		return err
	}

	return verify(string(b), res.Signature, robotPbKey)
}

func (signer signer) VerifyAccountSearchResponseSignature(res account.SearchResponse, robotPbKey string) error {
	json, err := json.Marshal(account.SearchResponse{
		EncryptedAddress: res.EncryptedAddress,
		EncryptedAESKey:  res.EncryptedAESKey,
		EncryptedWallet:  res.EncryptedWallet,
	})
	if err != nil {
		return err
	}

	return verify(string(json), res.Signature, robotPbKey)
}

func verify(data string, sig string, pubk string) error {
	var signature ecdsaSignature

	decodedkey, err := hex.DecodeString(pubk)
	if err != nil {
		return err
	}

	decodedsig, err := hex.DecodeString(sig)
	if err != nil {
		return err
	}

	pu, err := x509.ParsePKIXPublicKey(decodedkey)
	if err != nil {
		return err
	}

	ecdsaPublic := pu.(*ecdsa.PublicKey)
	asn1.Unmarshal(decodedsig, &signature)

	hash := []byte(hashString(data))

	if ecdsa.Verify(ecdsaPublic, hash, signature.R, signature.S) {
		return nil
	}

	return errors.New("Invalid signature")
}

func sign(data string, privk string) (string, error) {
	pvDecoded, err := hex.DecodeString(privk)
	if err != nil {
		return "", err
	}

	pv, err := x509.ParseECPrivateKey(pvDecoded)
	if err != nil {
		return "", err
	}

	hash := []byte(hashString(data))

	r, s, err := ecdsa.Sign(rand.Reader, pv, hash)
	if err != nil {
		return "", err
	}

	sig, err := asn1.Marshal(ecdsaSignature{r, s})
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sig), nil
}
