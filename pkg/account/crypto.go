package account

import uniris "github.com/uniris/uniris-cli/pkg"

//KeyGenerator describes methods for the keys generation for the enrollment
type KeyGenerator interface {

	//NewAESKey generate an AES key using derivation based on the given secret
	NewAESKey(secretDeriver string) (string, error)

	//NewKeyPair generate a ECDSA key pair from a given secret
	//
	//If the secret is a empty string, a random seed will be generated
	NewKeyPair(secret string) (uniris.KeyPair, error)
}

//Encrypter describes methods to perform encryption
type Encrypter interface {

	//EncryptString encrypts a string using a given public key
	EncryptString(str string, pvKey string) (string, error)

	//EncryptWallet encrypts a wallet with a given AES key
	EncryptWallet(w Wallet, AESKey string) (string, error)

	//EncryptID encrypts ID data with a given robot public key
	EncryptID(id ID, robotPubKey string) (string, error)

	//EncryptKeychain encrypts keychain data with the given robot public key
	EncryptKeychain(kc Keychain, robotPubKey string) (string, error)
}

//Decrypter defines methods to perform decryption
type Decrypter interface {

	//DecryptWallet decrypts a wallet using an AES key
	DecryptWallet(wallet, aesKey string) (Wallet, error)

	//DecryptString decrypts a string using the given private key
	DecryptString(str, pvKey string) (string, error)
}

//Signer describes methods to create signatures for the enrollment
type Signer interface {

	//SignString generate signature of a string
	SignString(str string, pvKey string) (string, error)

	//SignID generate signatures for the ID data
	SignID(id *ID, emPvKey, idPvKey string) error

	//SignKeychain generate signature for the keychain data
	SignKeychain(keychain *Keychain, emPvKey, idPvKey string) error

	//SignCreationRequest generate the signature request
	SignCreationRequest(req *CreationRequest, emPvKey string) error

	//VerifyCreationResultSignature verifies the signature of the account creation response
	VerifyCreationResultSignature(res CreationResult, sharedRobotPub string) error

	//VerifyAccountSearchResponseSignature verifies the signature of the account search response
	VerifyAccountSearchResponseSignature(res SearchResponse, sharedRobotPub string) error
}

//Hasher describes methods to create hash for the enrollment
type Hasher interface {

	//HashWallet process a hash from the given wallet
	HashWallet(w Wallet) (string, error)

	//HashString process string from a given string
	HashString(key string) string
}
