package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/urfave/cli"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
)

func main() {

	app := cli.NewApp()
	app.Name = "UNIRIS"
	app.Usage = "Playing with Nitrokey Smartcard"
	app.Version = "0.0.1"

	err := checkdep()
	if err != nil {
		log.Fatalf("Dependancies error: %s", err.Error())
	}

	err = checkSmartCard()
	if err != nil {
		log.Fatalf("SmartCard error: %s", err.Error())
	}

	app.Commands = []cli.Command{
		{
			Name:  "smartcard",
			Usage: "play with a smartcard ...",
			Subcommands: []cli.Command{
				{
					Name:  "getpub",
					Usage: "Retreive the public Key from the smartcard",
					Action: func(c *cli.Context) error {

						if c.NArg() != 2 {
							fmt.Printf("usage: getpub [keyid] [path_of_outputed_public_key]  \n")
							log.Fatalf("Not enough args")
						}
						err := exportPublicKey(c.Args().Get(0), c.Args().Get(1))
						if err != nil {
							log.Print(err)
						}
						return nil
					},
				},
				{
					Name:  "sign",
					Usage: "sign data",
					Action: func(c *cli.Context) error {
						if c.NArg() != 3 {
							fmt.Printf("usage: sign [keyid] [path_of_signature] [path_of_datafile]  \n")
							log.Fatalf("Not enough args")
						}
						err := sign(c.Args().Get(0), c.Args().Get(1), c.Args().Get(2))
						if err != nil {
							log.Print(err)
						}
						return nil
					},
				},
				{
					Name:  "verify",
					Usage: "verify a signature",
					Action: func(c *cli.Context) error {
						if c.NArg() != 3 {
							fmt.Printf("usage: verify [path_to_public_key] [path_of_signature] [path_of_datafile]  \n")
							log.Fatalf("Not enough args")
						}
						err := verify(c.Args().Get(0), c.Args().Get(1), c.Args().Get(2))
						if err != nil {
							log.Print(err)
						}
						return nil
					},
				},
				{
					Name:  "encrypt",
					Usage: "encrypt data",
					Action: func(c *cli.Context) error {
						if c.NArg() != 3 {
							fmt.Printf("usage: sign [keyid] [path_of_datafile] [path_of_cipher] \n")
							log.Fatalf("Not enough args")
						}
						err := encrypt(c.Args().Get(0), c.Args().Get(1), c.Args().Get(2))
						if err != nil {
							log.Print(err)
						}
						return nil
					},
				},
				{
					Name:  "decrypt",
					Usage: "decrypt data",
					Action: func(c *cli.Context) error {
						if c.NArg() != 3 {
							fmt.Printf("usage: sign [keyid] [path_of_cipher]  \n")
							log.Fatalf("Not enough args")
						}
						err := decrypt(c.Args().Get(0), c.Args().Get(1))
						if err != nil {
							log.Print(err)
						}
						return nil
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatalf("\n%s", err.Error())
	}

}

func verify(pubkeyPath string, signaturePath string, dataPath string) error {
	keyRingReader, err := os.Open(pubkeyPath)
	if err != nil {
		return err
	}

	signature, err := os.Open(signaturePath)
	if err != nil {
		return err
	}

	verification, err := os.Open(dataPath)
	if err != nil {
		return err
	}

	keyring, err := openpgp.ReadArmoredKeyRing(keyRingReader)
	if err != nil {
		return errors.New("Read Armored Key Ring: " + err.Error())
	}
	_, err = openpgp.CheckArmoredDetachedSignature(keyring, verification, signature)
	if err != nil {
		return errors.New("Check Detached Signature: " + err.Error())
	}

	fmt.Printf("OK")
	return nil
}

func sign(keyid string, signaturePath string, dataPath string) error {
	args := []string{"--sign", "--armor", "--detach", "--default-key", keyid, "-o", signaturePath, dataPath}
	err := pgpExecCmdQuiet(args)
	if err != nil {
		return err
	}

	sig, err := ioutil.ReadFile(signaturePath)
	if err != nil {
		return err
	}

	fmt.Printf("sig is: %s", string(sig))
	return nil
}

func encrypt(keyid string, dataPath string, cipherPath string) error {
	args := []string{"--encrypt", "-q", "--armor", "-r", keyid, "-o", cipherPath, dataPath}
	err := pgpExecCmdQuiet(args)
	if err != nil {
		return err
	}

	cipher, err := ioutil.ReadFile(cipherPath)
	if err != nil {
		return err
	}

	err = pgpCleanTempFiles(dataPath)
	if err != nil {
		return err
	}

	fmt.Printf("cipher is: %s", string(cipher))
	return nil
}

func decrypt(keyid string, cipherPath string) error {
	args := []string{"--decrypt", "-q", "--armor", "--default-key", keyid, cipherPath}
	clearData, err := pgpExecCmdOutput(args)
	if err != nil {
		return err
	}

	fmt.Printf("Clear data is: %s", string(clearData))
	return nil
}

func exportPublicKey(keyid string, pubkeyPath string) error {
	args := []string{"--export", "--armor", "default-key", keyid, "-o", pubkeyPath}
	res, err := pgpExecCmdOutput(args)
	if err != nil {
		return err
	}
	fmt.Printf("%s", res)
	return nil
}

func pgpExecCmdQuiet(args []string) error {
	cmd := exec.Command("gpg2", args...)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func pgpExecCmdOutput(args []string) (res string, err error) {
	cmd := exec.Command("gpg2", args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return "", err
	}
	return out.String(), nil
}

func pgpCleanTempFiles(filepath string) error {
	args := []string{"-r", filepath}
	cleanCmd := exec.Command("rm", args...)
	if err := cleanCmd.Run(); err != nil {
		return errors.New("cannot clean temp files")
	}
	return nil
}

func checkdep() error {
	cmd := exec.Command("gpg2", "--version")
	if err := cmd.Run(); err != nil {
		return errors.New("Gnupg is not installed, or Path is not correct")
	}
	return nil
}

func checkSmartCard() error {
	cmd := exec.Command("gpg2", "--card-status")
	if err := cmd.Run(); err != nil {
		return errors.New("Smartcard is not inserted")
	}
	return nil
}
