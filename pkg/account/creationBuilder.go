package account

import uniris "github.com/uniris/uniris-cli/pkg"

//Proposal represent a transaction proposal
type Proposal struct {
	SharedEmitterKeyPair ProposedKeyPair `json:"shared_emitter_kp"`
}

//ProposedKeyPair represent a key pair for a renew proposal
type ProposedKeyPair struct {
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	PublicKey           string `json:"public_key"`
}

//ID represents the data by will be encrypted by the client
type ID struct {
	PublicKey            string   `json:"pubk"`
	Hash                 string   `json:"hash"`
	EncryptedAESKey      string   `json:"encrypted_aes_key"`
	EncryptedAddrByID    string   `json:"encrypted_addr_id"`
	EncryptedAddrByRobot string   `json:"encrypted_addr_robot"`
	IDSignature          string   `json:"id_sig,omitempty"`
	EmitterSignature     string   `json:"em_sig,omitempty"`
	Proposal             Proposal `json:"proposal"`
}

//Keychain represents the data will be encrypted by the emitter
type Keychain struct {
	IDPublicKey          string   `json:"id_pubk"`
	EncryptedWallet      string   `json:"encrypted_wal"`
	EncryptedAddrByRobot string   `json:"encrypted_addr_robot"`
	IDSignature          string   `json:"id_sig,omitempty"`
	EmitterSignature     string   `json:"em_sig,omitempty"`
	Proposal             Proposal `json:"proposal"`
}

//CreationBuilder defines methods which represents the step to create an account
type creationBuilder struct {
	idKeys  uniris.KeyPair
	irisKey uniris.KeyPair
	aesKey  string

	hashWallet string
	addr       string
	idHash     string
	id         ID
	keychain   Keychain

	encWallet      string
	encID          string
	encKeychain    string
	encAddrByID    string
	encAddrByRobot string

	gen  KeyGenerator
	hash Hasher
	enc  Encrypter
	sign Signer
}

//GenerateKeys creates person keys, iris keys and the AES key
func (b *creationBuilder) GenerateKeys(secret string) error {

	idKeys, err := b.gen.NewKeyPair(secret)
	if err != nil {
		return err
	}

	b.idHash = b.hash.HashString(idKeys.PublicKey)

	b.idKeys = idKeys

	irisKeys, err := b.gen.NewKeyPair("")
	if err != nil {
		return err
	}

	b.irisKey = irisKeys

	aesKey, err := b.gen.NewAESKey(b.hash.HashString(idKeys.PrivateKey))
	if err != nil {
		return err
	}

	b.aesKey = aesKey

	return nil
}

//GenerateWallet creates a new wallet, store the hash and the encrypted wallet
func (b *creationBuilder) GenerateWallet() error {
	w := NewWallet(b.irisKey.PrivateKey)
	hashW, err := b.hash.HashWallet(w)
	if err != nil {
		return err
	}

	b.hashWallet = hashW
	encWallet, err := b.enc.EncryptWallet(w, b.aesKey)
	if err != nil {
		return err
	}
	b.encWallet = encWallet
	return nil
}

//GenerateAddresses creates addresses for the person and the robot by encrypted the hashed wallet
func (b *creationBuilder) GenerateAddresses(robotPubKey string) error {

	b.addr = b.hash.HashString(b.irisKey.PublicKey)
	encAddrByID, err := b.enc.EncryptString(b.addr, b.idKeys.PublicKey)
	if err != nil {
		return err
	}

	encAddrRobot, err := b.enc.EncryptString(b.addr, robotPubKey)
	if err != nil {
		return err
	}

	b.encAddrByID = encAddrByID
	b.encAddrByRobot = encAddrRobot

	return nil
}

//WrapData wraps the generate data into two distinct category id and keychain
func (b *creationBuilder) WrapData(lastSharedEmPubk string) error {
	encAesKey, err := b.enc.EncryptString(b.aesKey, b.idKeys.PublicKey)
	if err != nil {
		return err
	}

	sharedEmitterPropKeychain, err := b.gen.NewKeyPair("")
	if err != nil {
		return err
	}

	sharedEmitterPropKeychain.PrivateKey, err = b.enc.EncryptString(sharedEmitterPropKeychain.PrivateKey, lastSharedEmPubk)
	if err != nil {
		return err
	}

	sharedEmitterPropID, err := b.gen.NewKeyPair("")
	if err != nil {
		return err
	}

	sharedEmitterPropID.PrivateKey, err = b.enc.EncryptString(sharedEmitterPropID.PrivateKey, lastSharedEmPubk)
	if err != nil {
		return err
	}

	b.id = ID{
		EncryptedAESKey:      encAesKey,
		Hash:                 b.idHash,
		EncryptedAddrByID:    b.encAddrByID,
		EncryptedAddrByRobot: b.encAddrByRobot,
		PublicKey:            b.idKeys.PublicKey,
		Proposal: Proposal{
			SharedEmitterKeyPair: ProposedKeyPair{
				EncryptedPrivateKey: sharedEmitterPropID.PrivateKey,
				PublicKey:           sharedEmitterPropID.PublicKey,
			},
		},
	}

	b.keychain = Keychain{
		EncryptedAddrByRobot: b.encAddrByRobot,
		EncryptedWallet:      b.encWallet,
		IDPublicKey:          b.idKeys.PublicKey,
		Proposal: Proposal{
			SharedEmitterKeyPair: ProposedKeyPair{
				EncryptedPrivateKey: sharedEmitterPropKeychain.PrivateKey,
				PublicKey:           sharedEmitterPropKeychain.PublicKey,
			},
		},
	}

	return nil
}

//GenerateDataSignatures creates signatures for the id and keychain data
func (b *creationBuilder) GenerateDataSignatures(emPv string) error {

	if err := b.sign.SignID(&b.id, emPv, b.idKeys.PrivateKey); err != nil {
		return err
	}

	if err := b.sign.SignKeychain(&b.keychain, emPv, b.idKeys.PrivateKey); err != nil {
		return err
	}

	return nil
}

//EncryptData performs encryption on the id and keychain data
func (b *creationBuilder) EncryptData(sharedRobotPbKey string) error {
	encID, err := b.enc.EncryptID(b.id, sharedRobotPbKey)
	if err != nil {
		return err
	}

	encKeychain, err := b.enc.EncryptKeychain(b.keychain, sharedRobotPbKey)
	if err != nil {
		return err
	}

	b.encID = encID
	b.encKeychain = encKeychain

	return nil
}

//BuildRequest creates the request to be send to the blockchain
func (b *creationBuilder) BuildAndSignRequest(lastSharedEmitPv string) (*CreationRequest, error) {

	req := &CreationRequest{
		EncryptedID:       b.encID,
		EncryptedKeychain: b.encKeychain,
	}

	if err := b.sign.SignCreationRequest(req, lastSharedEmitPv); err != nil {
		return nil, err
	}

	return req, nil
}
