package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uniris/uniris-cli/pkg/account"
)

/*
Scenario: Sign and verify hashed data
	Given an hashed data and a key pari
	When I want sign this data
	Then I get the signature and can be verify by the public key associated
*/
func TestSignAndVerify(t *testing.T) {

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	data := "data"

	sig, err := sign(data, hex.EncodeToString(pvKey))
	assert.Nil(t, err)
	assert.NotEmpty(t, sig)

	err = verify(data, sig, hex.EncodeToString(pubKey))
	assert.Nil(t, err)
}

/*
Scenario: Sign an ID data
	Given an account ID
	When I want to sign it
	Then I get two signatures Emitter and ID that I can verify
*/
func TestSignId(t *testing.T) {
	id := account.ID{
		EncryptedAddrByID:    "enc addr",
		EncryptedAddrByRobot: "enc addr",
		EncryptedAESKey:      "enc aes key",
		Hash:                 "hash",
		PublicKey:            "pub key",
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	s := NewSigner()
	err := s.SignID(&id, hex.EncodeToString(pvKey), hex.EncodeToString(pvKey))
	assert.Nil(t, err)

	assert.NotEmpty(t, id.EmitterSignature)
	assert.NotEmpty(t, id.IDSignature)

	oldID := account.ID{
		EncryptedAddrByID:    "enc addr",
		EncryptedAddrByRobot: "enc addr",
		EncryptedAESKey:      "enc aes key",
		Hash:                 "hash",
		PublicKey:            "pub key",
	}

	b, _ := json.Marshal(oldID)

	assert.Nil(t, verify(string(b), id.EmitterSignature, hex.EncodeToString(pubKey)))
	assert.Nil(t, verify(string(b), id.IDSignature, hex.EncodeToString(pubKey)))
}

/*
Scenario: Sign a keychain data
	Given an account Keychain
	When I want to sign it
	Then I get two signatures Emitter and ID that I can verify
*/
func TestSignKeychain(t *testing.T) {
	kc := account.Keychain{
		EncryptedAddrByRobot: "enc addr",
		EncryptedWallet:      "enc wallet",
		IDPublicKey:          "pub key",
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	s := NewSigner()
	err := s.SignKeychain(&kc, hex.EncodeToString(pvKey), hex.EncodeToString(pvKey))
	assert.Nil(t, err)

	assert.NotEmpty(t, kc.EmitterSignature)
	assert.NotEmpty(t, kc.IDSignature)

	oldKC := account.Keychain{
		EncryptedAddrByRobot: "enc addr",
		EncryptedWallet:      "enc wallet",
		IDPublicKey:          "pub key",
	}

	b, _ := json.Marshal(oldKC)

	assert.Nil(t, verify(string(b), kc.EmitterSignature, hex.EncodeToString(pubKey)))
	assert.Nil(t, verify(string(b), kc.IDSignature, hex.EncodeToString(pubKey)))
}

/*
Scenario: Sign an account creation request
	Given an account creation request
	When I want to sign it
	Then I get a request signature that I can verify
*/
func TestSignCreationRequest(t *testing.T) {
	r := account.CreationRequest{
		EncryptedID:       "enc id",
		EncryptedKeychain: "enc keychain",
	}

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	NewSigner().SignCreationRequest(&r, hex.EncodeToString(pvKey))

	oldR := account.CreationRequest{
		EncryptedID:       "enc id",
		EncryptedKeychain: "enc keychain",
	}

	b, _ := json.Marshal(oldR)

	assert.Nil(t, verify(string(b), r.Signature, hex.EncodeToString(pubKey)))
}

/*
Scenario: Verify creation result
	Given a creation result with signature response
	When I want to verify it
	Then I get not error
*/
func TestVerifyCreationResult(t *testing.T) {

	res := account.CreationResult{
		Transactions: account.CreationTransactions{
			ID: account.Transaction{
				MasterPeerIP:    "ip",
				Signature:       "sig",
				TransactionHash: "hash",
			},
		},
	}

	b, _ := json.Marshal(res)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	sig, _ := sign(string(b), hex.EncodeToString(pvKey))

	res.Signature = sig

	assert.Nil(t, NewSigner().VerifyCreationResultSignature(res, hex.EncodeToString(pubKey)))

}

/*
Scenario: Verify creation result
	Given a creation result with signature response
	When I want to verify it
	Then I get not error
*/
func TestVerifySearchAccountSignature(t *testing.T) {

	res := account.SearchResponse{
		EncryptedAddress: "enc addr",
		EncryptedAESKey:  "enc aes",
		EncryptedWallet:  "enc wallet",
	}

	b, _ := json.Marshal(res)

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pvKey, _ := x509.MarshalECPrivateKey(key)
	pubKey, _ := x509.MarshalPKIXPublicKey(key.Public())

	sig, _ := sign(string(b), hex.EncodeToString(pvKey))

	res.Signature = sig

	assert.Nil(t, NewSigner().VerifyAccountSearchResponseSignature(res, hex.EncodeToString(pubKey)))

}
