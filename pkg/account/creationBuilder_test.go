package account

import (
	"testing"

	"github.com/stretchr/testify/assert"
	uniris "github.com/uniris/uniris-cli/pkg"
)

/*
Scenario: Generate keys
	Given a secret
	When we want generate keys
	Then we get three generated keys (person, iris, aes)
*/
func TestGenerateKeys(t *testing.T) {
	b := &creationBuilder{
		gen:  mockKeyGenerator{},
		hash: mockHasher{},
	}

	err := b.GenerateKeys("secret")
	assert.Nil(t, err)
	assert.NotEmpty(t, b.idKeys)
	assert.NotEmpty(t, b.irisKey)
	assert.NotEmpty(t, b.aesKey)

	assert.Equal(t, "aeskey", b.aesKey)
	assert.Equal(t, "privatekey", b.idKeys.PrivateKey)
	assert.Equal(t, "publickey", b.idKeys.PublicKey)
	assert.Equal(t, "privatekey", b.irisKey.PrivateKey)
	assert.Equal(t, "publickey", b.irisKey.PublicKey)
}

/*
Scenario: Generate wallet
	Given keys generated
	When I ask to generate the wallet
	Then I can get the encrypted wallet with the AES key and the hash of the wallet
*/
func TestGenerateWallet(t *testing.T) {
	b := creationBuilder{
		gen:  mockKeyGenerator{},
		enc:  mockEncrypter{},
		hash: mockHasher{},
	}

	b.GenerateKeys("secret")

	err := b.GenerateWallet()
	assert.Nil(t, err)

	assert.NotEmpty(t, b.encWallet)
	assert.NotEmpty(t, b.hashWallet)
}

/*
Scenario: Generate addresses
	Given a wallet generated
	When I ask to generate the addresses
	Then I get two addresses for the person and for person equal to the encrypted hashed
*/
func TestGenerateAddresses(t *testing.T) {
	b := creationBuilder{
		gen:  mockKeyGenerator{},
		enc:  mockEncrypter{},
		hash: mockHasher{},
	}

	b.GenerateKeys("secret")
	b.GenerateWallet()

	err := b.GenerateAddresses("robotkey")
	assert.Nil(t, err)

	assert.Equal(t, "encrypted_string", b.encAddrByID)
	assert.Equal(t, "encrypted_string", b.encAddrByRobot)
}

/*
Scenario: Wrap generated data
	Given keys, wallet and addresses generated
	When I ask to wrap the data given a emitter key pair
	Then I get the id data and keychain data
*/
func TestWrapData(t *testing.T) {
	b := creationBuilder{
		gen:  mockKeyGenerator{},
		enc:  mockEncrypter{},
		hash: mockHasher{},
	}

	b.GenerateKeys("secret")
	b.GenerateWallet()
	b.GenerateAddresses("robotkey")

	sharedEmKeyPair := uniris.KeyPair{
		PrivateKey: "private key",
		PublicKey:  "public key",
	}
	err := b.WrapData(sharedEmKeyPair.PublicKey)
	assert.Nil(t, err)

	assert.Equal(t, "publickey", b.id.PublicKey)
	assert.NotNil(t, "data hashed", b.id.Hash)
	assert.NotNil(t, "encrypted_aes_key", b.id.EncryptedAESKey)
	assert.NotNil(t, b.id.EncryptedAddrByID)
	assert.NotNil(t, b.id.EncryptedAddrByRobot)
	assert.NotNil(t, "publickey", b.keychain.IDPublicKey)
	assert.NotNil(t, "wallet encrypted", b.keychain.EncryptedWallet)
	assert.NotNil(t, b.keychain.EncryptedAddrByRobot)
	assert.NotEmpty(t, b.keychain.Proposal.SharedEmitterKeyPair.EncryptedPrivateKey)
	assert.NotEmpty(t, b.keychain.Proposal.SharedEmitterKeyPair.PublicKey)
	assert.NotEmpty(t, b.id.Proposal.SharedEmitterKeyPair.EncryptedPrivateKey)
	assert.NotEmpty(t, b.id.Proposal.SharedEmitterKeyPair.PublicKey)
}

/*
Scenario: Generate signatures for the generate data
	Given data wrapped
	When I generate signatures
	Then I get 4 signatures (2 for id data and 2 for keychain data)
*/
func TestGenerateDataSignatures(t *testing.T) {
	b := creationBuilder{
		gen:  mockKeyGenerator{},
		enc:  mockEncrypter{},
		hash: mockHasher{},
		sign: mockSigner{},
	}

	b.GenerateKeys("secret")

	sharedEmKeyPair := uniris.KeyPair{
		PrivateKey: "private key",
		PublicKey:  "public key",
	}
	b.WrapData(sharedEmKeyPair.PublicKey)

	err := b.GenerateDataSignatures("private key")
	assert.Nil(t, err)
	assert.Equal(t, "sig", b.id.EmitterSignature)
	assert.NotNil(t, "sig", b.id.IDSignature)

	assert.NotNil(t, "sig", b.keychain.IDSignature)
	assert.NotNil(t, "sig", b.keychain.EmitterSignature)
}

/*
Scenario: Encrypt data
	Given data wrapped and a robot public key
	When I want to encrypt the data
	Then I get the id and keychain data encrypted
*/
func TestEncryptData(t *testing.T) {
	b := creationBuilder{
		gen:  mockKeyGenerator{},
		enc:  mockEncrypter{},
		hash: mockHasher{},
		sign: mockSigner{},
	}

	b.GenerateKeys("secret")

	sharedEmKeyPair := uniris.KeyPair{
		PrivateKey: "private key",
		PublicKey:  "public key",
	}
	b.WrapData(sharedEmKeyPair.PublicKey)

	err := b.EncryptData("robotkey")
	assert.Nil(t, err)

	assert.Equal(t, "encrypted id data", b.encID)
	assert.NotNil(t, "encrypted wallet data", b.encKeychain)
}

/*
Scenario: Build request
	Given keys, wallet generated, data wrapped, signed and encrypted
	When I ask to build the request
	Then I get the a new instance of the request with the encrypted data and the signatures
*/
func TestBuildRequest(t *testing.T) {
	b := creationBuilder{
		gen:  mockKeyGenerator{},
		enc:  mockEncrypter{},
		hash: mockHasher{},
		sign: mockSigner{},
	}

	b.GenerateKeys("secret")
	b.GenerateWallet()

	sharedEmKeyPair := uniris.KeyPair{
		PrivateKey: "private key",
		PublicKey:  "public key",
	}
	b.WrapData(sharedEmKeyPair.PublicKey)
	b.GenerateDataSignatures("em private key")
	b.EncryptData("robotkey")

	req, err := b.BuildAndSignRequest(sharedEmKeyPair.PrivateKey)
	assert.Nil(t, err)
	assert.NotNil(t, req)

	assert.Equal(t, "encrypted id data", req.EncryptedID)
	assert.Equal(t, "encrypted keychain data", req.EncryptedKeychain)
	assert.Equal(t, "sig", req.Signature)
}
