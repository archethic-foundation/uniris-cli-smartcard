package account

import (
	"testing"

	"github.com/uniris/uniris-cli/pkg"

	"github.com/stretchr/testify/assert"
)

/*
Scenario: Retrieve an account
	Given a secret
	When we want retreive an account, we generate a public key
	Then we request the blockchain, get the encrypted data and decrypt it
*/
func TestGetAccount(t *testing.T) {
	srv := NewService(
		mockKeyGenerator{},
		mockEncrypter{},
		mockDecrypter{},
		mockHasher{},
		mockSigner{},
		mockBlockchainClient{})

	sk := uniris.SharedKeys{
		Robot: "robotkey",
		Emitter: []uniris.KeyPair{
			uniris.KeyPair{
				PrivateKey: "pvKey",
			},
		},
	}

	details, err := srv.GetAccount("secret", sk)
	assert.Nil(t, err)
	assert.Equal(t, "decrypted string", details.Addr)
	assert.Equal(t, "iris key", details.Wallet.Services["IRIS"].PrivateKey)
}

/*
Scenario: Enroll a new user
	Given a secret
	When we enroll a user
	Then we generate a wallet and an encrypted request associated in a file
*/
func TestEnroll(t *testing.T) {

	srv := NewService(
		mockKeyGenerator{},
		mockEncrypter{},
		mockDecrypter{},
		mockHasher{},
		mockSigner{},
		mockBlockchainClient{})

	sk := uniris.SharedKeys{
		Robot: "robotkey",
		Emitter: []uniris.KeyPair{
			uniris.KeyPair{
				PrivateKey: "pvKey",
				PublicKey:  "pub key",
			},
		},
	}
	ack, err := srv.CreateAccount("secret", sk)
	assert.Nil(t, err)
	assert.Equal(t, "transaction hash", ack.Transactions.ID.TransactionHash)
	assert.Equal(t, "transaction hash", ack.Transactions.Keychain.TransactionHash)
}

type mockKeyGenerator struct {
}

func (g mockKeyGenerator) NewAESKey(secret string) (string, error) {
	return "aeskey", nil
}

func (g mockKeyGenerator) NewKeyPair(secret string) (uniris.KeyPair, error) {
	return uniris.KeyPair{
		PrivateKey: "privatekey",
		PublicKey:  "publickey",
	}, nil
}

type mockEncrypter struct{}

func (e mockEncrypter) EncryptString(str string, pubKey string) (string, error) {
	return "encrypted_string", nil
}

func (e mockEncrypter) EncryptWallet(w Wallet, walletCipherKey string) (string, error) {
	return "wallet encrypted", nil
}
func (e mockEncrypter) EncryptID(id ID, robotPubKey string) (string, error) {
	return "encrypted id data", nil
}
func (e mockEncrypter) EncryptKeychain(kc Keychain, robotPubKey string) (string, error) {
	return "encrypted keychain data", nil
}

type mockDecrypter struct{}

func (e mockDecrypter) DecryptString(str, pvKey string) (string, error) {
	return "decrypted string", nil
}
func (e mockDecrypter) DecryptWallet(wallet, aesKey string) (Wallet, error) {
	return NewWallet("iris key"), nil
}

type mockHasher struct{}

func (h mockHasher) HashString(data string) string {
	return "string hashed"
}

func (h mockHasher) HashWallet(w Wallet) (string, error) {
	return "hashed wallet data", nil
}

type mockSigner struct{}

func (s mockSigner) SignID(id *ID, emPvKey, idPvKey string) error {
	id.IDSignature = "sig"
	id.EmitterSignature = "sig"
	return nil
}

func (s mockSigner) SignKeychain(kc *Keychain, emPvKey, idPvKey string) error {
	kc.IDSignature = "sig"
	kc.EmitterSignature = "sig"
	return nil
}

func (s mockSigner) SignCreationRequest(req *CreationRequest, pvKey string) error {
	req.Signature = "sig"
	return nil
}

func (s mockSigner) SignString(str string, pvKey string) (string, error) {
	return "sig", nil
}

func (s mockSigner) VerifyCreationResultSignature(res CreationResult, robotPbKey string) error {
	return nil
}

func (s mockSigner) VerifyAccountSearchResponseSignature(res SearchResponse, sharedRobotPub string) error {
	return nil
}

type mockBlockchainClient struct{}

func (w mockBlockchainClient) GetAccount(req SearchRequest) (*SearchResponse, error) {
	return &SearchResponse{
		EncryptedAddress: "enc addr",
		EncryptedAESKey:  "enc aes key",
		EncryptedWallet:  "enc wallet",
		Signature:        "sig",
	}, nil
}

func (w mockBlockchainClient) CreateAccount(req CreationRequest) (*CreationResult, error) {
	return &CreationResult{
		Transactions: CreationTransactions{
			ID: Transaction{
				TransactionHash: "transaction hash",
			},
			Keychain: Transaction{
				TransactionHash: "transaction hash",
			},
		},
		Signature: "sig",
	}, nil
}

func (w mockBlockchainClient) CheckAccountExist(req SearchRequest) (bool, error) {
	return false, nil
}

type mockAccountService struct{}

func (a mockAccountService) GetAccount(secret string) (*Details, error) {
	return nil, nil
}
