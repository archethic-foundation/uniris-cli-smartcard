package account

import (
	"errors"

	"github.com/uniris/uniris-cli/pkg"
)

//ErrAccountAlreadyExist is returned when the public key generated already exist
var ErrAccountAlreadyExist = errors.New("This account already exists. Please uses an unique passphrase")

//ErrAccountDoesNotExist is returned when the request account doest not exist
var ErrAccountDoesNotExist = errors.New("The account requested does not exist")

//RobotClient defines methods to interact with the robot
type RobotClient interface {
	CheckAccountExist(req SearchRequest) (bool, error)
	CreateAccount(CreationRequest) (*CreationResult, error)
	GetAccount(req SearchRequest) (*SearchResponse, error)
}

//Service define the enrollment methods
type Service interface {
	CreateAccount(secret string, sharedKeys uniris.SharedKeys) (*Result, error)
	GetAccount(secret string, sharedKeys uniris.SharedKeys) (*Details, error)
}

type service struct {
	gen  KeyGenerator
	enc  Encrypter
	dec  Decrypter
	hash Hasher
	sign Signer
	cli  RobotClient
}

//NewService create an enrollement service
func NewService(gen KeyGenerator, enc Encrypter, dec Decrypter, hash Hasher, sign Signer, cli RobotClient) Service {
	return service{
		gen:  gen,
		enc:  enc,
		dec:  dec,
		hash: hash,
		sign: sign,
		cli:  cli,
	}
}

func (srv service) CreateAccount(secret string, sharedKeys uniris.SharedKeys) (*Result, error) {

	b := creationBuilder{
		gen:  srv.gen,
		hash: srv.hash,
		enc:  srv.enc,
		sign: srv.sign,
	}

	//Derive keys from the provided secret
	if err := b.GenerateKeys(secret); err != nil {
		return nil, err
	}

	//Checks if the account doest not exist already
	err := srv.preventIfExist(b.idKeys.PublicKey, sharedKeys)
	if err != nil {
		return nil, err
	}

	//Building account and wallet
	if err := b.GenerateWallet(); err != nil {
		return nil, err
	}
	if err := b.GenerateAddresses(sharedKeys.Robot); err != nil {
		return nil, err
	}

	randomKeyPair := sharedKeys.RandomEmitterKey()

	if err := b.WrapData(randomKeyPair.PublicKey); err != nil {
		return nil, err
	}
	if err := b.GenerateDataSignatures(randomKeyPair.PrivateKey); err != nil {
		return nil, err
	}
	if err := b.EncryptData(sharedKeys.Robot); err != nil {
		return nil, err
	}

	//Sending the account to the blockchain
	req, err := b.BuildAndSignRequest(sharedKeys.RequestEmitterKey().PrivateKey)
	if err != nil {
		return nil, err
	}
	res, err := srv.cli.CreateAccount(*req)
	if err != nil {
		return nil, err
	}

	//Checks if the enrollment result is valid
	if err := srv.sign.VerifyCreationResultSignature(*res, sharedKeys.Robot); err != nil {
		return nil, err
	}

	return &Result{
		Transactions: res.Transactions,
		Address:      b.addr,
	}, nil
}

func (srv service) GetAccount(secret string, sharedKeys uniris.SharedKeys) (*Details, error) {
	//Regenerate key pair with the provided secret
	idKeys, err := srv.gen.NewKeyPair(secret)
	if err != nil {
		return nil, err
	}

	//Request the blockchain to retrieve the account
	req, err := srv.buildAccountRequest(idKeys.PublicKey, sharedKeys.Robot, sharedKeys.RequestEmitterKey().PrivateKey)
	if err != nil {
		return nil, err
	}

	res, err := srv.cli.GetAccount(req)
	if err != nil {
		return nil, err
	}

	//Verify the result from the blockchain
	if err := srv.sign.VerifyAccountSearchResponseSignature(*res, sharedKeys.Robot); err != nil {
		return nil, err
	}

	//Decrypt returned results
	decryptedAesKey, err := srv.dec.DecryptString(res.EncryptedAESKey, idKeys.PrivateKey)
	if err != nil {
		return nil, err
	}

	decryptedWallet, err := srv.dec.DecryptWallet(res.EncryptedWallet, decryptedAesKey)
	if err != nil {
		return nil, err
	}

	decryptedAddr, err := srv.dec.DecryptString(res.EncryptedAddress, idKeys.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &Details{
		Addr:   decryptedAddr,
		Wallet: decryptedWallet,
	}, nil

}

func (srv service) preventIfExist(idPubKey string, sharedKeys uniris.SharedKeys) error {
	req, err := srv.buildAccountRequest(idPubKey, sharedKeys.Robot, sharedKeys.RequestEmitterKey().PrivateKey)
	if err != nil {
		return err
	}

	exist, err := srv.cli.CheckAccountExist(req)
	if err != nil {
		return err
	}
	if exist {
		return ErrAccountAlreadyExist
	}
	return nil
}

func (srv service) buildAccountRequest(idPubKey, sharedRobotPbKey, sharedEmPvKey string) (res SearchRequest, err error) {
	idHash := srv.hash.HashString(idPubKey)
	encIDHash, err := srv.enc.EncryptString(idHash, sharedRobotPbKey)
	if err != nil {
		return
	}
	sig, err := srv.sign.SignString(encIDHash, sharedEmPvKey)
	if err != nil {
		return
	}
	return SearchRequest{
		EncIDHash: encIDHash,
		Signature: sig,
	}, nil
}
