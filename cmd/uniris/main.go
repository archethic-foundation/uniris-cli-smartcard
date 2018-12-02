package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	uniris "github.com/uniris/uniris-cli/pkg"
	"github.com/uniris/uniris-cli/pkg/account"
	"golang.org/x/crypto/ssh/terminal"
	yaml "gopkg.in/yaml.v2"

	"github.com/uniris/uniris-cli/pkg/transport/rest"

	"github.com/uniris/uniris-cli/pkg/crypto"

	"github.com/urfave/cli"
)

func main() {

	rand.Seed(time.Now().UnixNano())

	app := cli.NewApp()
	app.Name = "UNIRIS"
	app.Usage = "Interact with the UNIRIS blockchain"
	app.Version = "0.0.1"

	sharedKeys, err := loadSharedKeys()
	if err != nil {
		log.Fatalf("Cannot load shared keys - %s", err.Error())
	}

	keygen := crypto.NewKeyGenerator()
	encrypter := crypto.NewEncrypter()
	decrypter := crypto.NewDecrypter()
	hasher := crypto.NewHasher()
	signer := crypto.NewSigner()
	robotCli := rest.NewRobotClient()

	accountSrv := account.NewService(keygen, encrypter, decrypter, hasher, signer, robotCli)

	app.Commands = []cli.Command{
		{
			Name:  "account",
			Usage: "Manage accounts",
			Subcommands: []cli.Command{
				{
					Name:  "get",
					Usage: "Retreive an UNIRIS account",
					Action: func(c *cli.Context) error {
						return getAccount(accountSrv, sharedKeys)
					},
				},
				{
					Name:  "new",
					Usage: "Create a new account by creating a wallet",
					Action: func(c *cli.Context) error {
						return createAccount(accountSrv, sharedKeys)
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("\n%s", err.Error())
	}

}

func getAccount(accountSrv account.Service, sharedKeys uniris.SharedKeys) error {
	fmt.Print("Enter a passphrase [replacement of fingerprint]")
	secret, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	secretStr := string(secret)
	secretStr = strings.Trim(secretStr, "\n")

	details, err := accountSrv.GetAccount(secretStr, sharedKeys)
	if err != nil {
		return err
	}

	fmt.Printf("\nAddress: %s\n", details.Addr)
	fmt.Println("Wallet")
	fmt.Println("- Services")
	for name, service := range details.Wallet.Services {
		fmt.Printf("  - %s\n", name)
		fmt.Printf("    - Key: %s\n", service.PrivateKey)
	}

	return nil
}

func createAccount(accSrv account.Service, sharedKeys uniris.SharedKeys) error {
	fmt.Print("Enter a passphrase [replacement of fingerprint]")

	secret, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return err
	}
	secretStr := string(secret)
	secretStr = strings.Trim(secretStr, "\n")

	if secretStr == "" {
		return errors.New("Passphrase required")
	}

	ack, err := accSrv.CreateAccount(secretStr, sharedKeys)
	if err != nil {
		return err
	}

	fmt.Printf("\nGenerated address: %s\n", ack.Address)

	fmt.Print("Transactions\n")
	fmt.Print("  ID:\n")
	fmt.Printf("   - Transaction hash: %s\n", ack.Transactions.ID.TransactionHash)
	fmt.Printf("   - Master peer IP: %s\n", ack.Transactions.ID.MasterPeerIP)

	fmt.Print("  Keychain:\n")
	fmt.Printf("   - Transaction hash: %s\n", ack.Transactions.Keychain.TransactionHash)
	fmt.Printf("   - Master peer IP: %s\n", ack.Transactions.Keychain.MasterPeerIP)

	return nil
}

func loadSharedKeys() (shared uniris.SharedKeys, err error) {
	keysDir, err := filepath.Abs("keys")
	if err != nil {
		return
	}
	sharedJSON, err := ioutil.ReadFile(path.Join(keysDir, "shared.yaml"))
	if err != nil {
		return
	}

	if err = yaml.Unmarshal(sharedJSON, &shared); err != nil {
		return
	}

	shared.SortEmitterKeys()

	return shared, nil
}
