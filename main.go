package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	"github.com/jessevdk/go-flags"
	"github.com/ubuntu-core/snappy/asserts"
)

func main() {
	parser := flags.NewParser(nil, flags.Default)
	parser.AddCommand(
		"key",
		"generate new key",
		"generate new key that can be used to sign assertions",
		&keyCmd{},
	)
	parser.AddCommand(
		"assertion",
		"generate new assertion",
		"generate an assertion, signed by the assertion's authority-id",
		&assertionCmd{},
	)
	parser.AddCommand(
		"check",
		"check assertion chain",
		"check assertions chain can be loaded",
		&checkCmd{},
	)

	_, err := parser.ParseArgs(os.Args)
	if err != nil {
		os.Exit(1)
	}
}

// keyCmd is used to generate a new private key.
type keyCmd struct{}

func (cmd *keyCmd) Execute(args []string) error {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyPacket := packet.NewRSAPrivateKey(time.Now(), rsaKey)
	encodedPubKey, err := asserts.EncodePublicKey(asserts.OpenPGPPrivateKey(keyPacket).PublicKey())
	if err != nil {
		return err
	}

	encodedPubKey = []byte(strings.Replace(string(encodedPubKey), "\n", "", -1))

	log.Printf("public-key-id: %x", keyPacket.PublicKey.KeyId)
	log.Printf("public-key-fingerprint: %x", keyPacket.PublicKey.Fingerprint)
	log.Printf("public-key: %s", encodedPubKey)

	w, err := armor.Encode(os.Stdout, openpgp.PrivateKeyType, nil)
	if err != nil {
		return err
	}
	keyPacket.Serialize(w)
	w.Close()

	return nil
}

// assertionCmd is used to sign a new assertion.
type assertionCmd struct {
	SigningKeys map[string]string `short:"s" long:"signing-key" description:"signing key" required:"1"`
	Args        struct {
		FileName string `positional-arg-name:"file-name" required:"1"`
	} `positional-args:"1"`
}

func (cmd *assertionCmd) Execute(args []string) error {
	db, err := openDatabase(nil)
	if err != nil {
		return err
	}

	signingKeys, err := readSigningKeys(cmd.SigningKeys)
	if err != nil {
		return err
	}

	for authorityID, key := range signingKeys {
		err = db.ImportKey(authorityID, key)
		if err != nil {
			return fmt.Errorf("error importing key for %s (%s)", authorityID, err.Error())
		}
		log.Printf("imported signing key authority-id=%q key-id=%q", authorityID, key.PublicKey().ID())
	}

	f, err := os.Open(cmd.Args.FileName)
	if err != nil {
		return err
	}
	defer f.Close()

	assertData := new(struct {
		Headers map[string]string
		Content string
	})
	err = json.NewDecoder(f).Decode(assertData)
	if err != nil {
		panic(err)
		return err
	}

	assertType := asserts.Type(assertData.Headers["type"])
	if assertType == nil {
		return fmt.Errorf("invalid assertion type %q", assertData.Headers["type"])
	}
	signingKey, ok := signingKeys[assertData.Headers["authority-id"]]
	if !ok {
		return fmt.Errorf("no signing key for %q", assertData.Headers["authority-id"])
	}
	keyID := signingKey.PublicKey().ID()
	assert, err := db.Sign(assertType, assertData.Headers, []byte(assertData.Content), keyID)
	if err != nil {
		return err
	}

	encodedAssert := asserts.Encode(assert)
	fmt.Printf(string(encodedAssert))

	return nil
}

// checkCmd is used to verify a chain of assertions.
type checkCmd struct {
	TrustedKeys []string `short:"t" long:"trusted-key" description:"trusted key" required:"1"`
	Args        struct {
		FileNames []string `positional-arg-name:"file-name" required:"1"`
	} `positional-args:"1"`
}

func (cmd *checkCmd) Execute(args []string) error {
	trustedKeys, err := readAccountKeys(cmd.TrustedKeys)
	if err != nil {
		return err
	}

	db, err := openDatabase(trustedKeys)
	if err != nil {
		return err
	}

	for _, assertPath := range cmd.Args.FileNames {
		log.Printf("adding %s", assertPath)
		assert, err := readAssertion(assertPath)
		if err != nil {
			return err
		}
		err = db.Add(assert)
		if err != nil {
			return err
		}
	}

	log.Println("ok")

	return nil
}

func openDatabase(trustedKeys []*asserts.AccountKey) (*asserts.Database, error) {
	db, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore:      asserts.NewMemoryBackstore(),
		KeypairManager: asserts.NewMemoryKeypairManager(),
		TrustedKeys:    trustedKeys,
	})
	if err != nil {
		return nil, err
	}
	return db, nil
}

func readSigningKeys(signingKeys map[string]string) (map[string]asserts.PrivateKey, error) {
	out := make(map[string]asserts.PrivateKey, len(signingKeys))
	for authorityID, keyFile := range signingKeys {
		authorityID = strings.TrimSpace(authorityID)
		keyFile = strings.TrimSpace(keyFile)
		key, err := readPrivatePGPKey(keyFile)
		if err != nil {
			return nil, fmt.Errorf("error reading key for %s (%s)", authorityID, err.Error())
		}
		out[authorityID] = key
	}
	return out, nil
}

func readPrivatePGPKey(path string) (asserts.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	block, err := armor.Decode(f)
	if err != nil {
		log.Fatal(err)
	}
	if block.Type != openpgp.PrivateKeyType {
		return nil, fmt.Errorf("invalid type, expected %q got %q", openpgp.PrivateKeyType, block.Type)
	}

	p, err := packet.Read(block.Body)
	if err != nil {
		panic(err)
		log.Fatal(err)
	}

	privateKey, ok := p.(*packet.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not a private key")
	}

	return asserts.OpenPGPPrivateKey(privateKey), nil
}

func readAccountKeys(paths []string) ([]*asserts.AccountKey, error) {
	accountKeys := make([]*asserts.AccountKey, len(paths))
	for i, path := range paths {
		accountKey, err := readAccountKey(path)
		if err != nil {
			return nil, err
		}
		accountKeys[i] = accountKey
	}
	return accountKeys, nil
}

func readAccountKey(path string) (*asserts.AccountKey, error) {
	assertion, err := readAssertion(path)
	if err != nil {
		return nil, err
	}
	accountKey, ok := assertion.(*asserts.AccountKey)
	if !ok {
		return nil, fmt.Errorf("not an account-key")
	}
	return accountKey, nil
}

func readAssertion(path string) (asserts.Assertion, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return asserts.Decode(data)
}
