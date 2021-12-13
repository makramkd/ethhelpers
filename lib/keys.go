package lib

import (
	stdcrypto "crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
)

// GenPair generates a (private, public) key pair suitable for use
// on any ethereum network.
func GenPair() (*ecdsa.PrivateKey, stdcrypto.PublicKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, err
	}

	return privateKey, privateKey.Public(), nil
}

// SaveAddress generates the EIP55-compliant hex string representation
// of the address associated with the given public key and saves it to the given
// io.Writer.
func SaveAddress(pubKey stdcrypto.PublicKey, out io.Writer) error {
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("error casting public key to ecdsa")
	}

	address := crypto.PubkeyToAddress(*ecdsaPubKey).Hex()

	_, err := io.WriteString(out, address)
	return err
}

func GetAddress(privKey string) (string, error) {
	b, err := hex.DecodeString(privKey)
	if err != nil {
		return "", err
	}
	d := new(big.Int).SetBytes(b)

	pkX, pkY := crypto.S256().ScalarBaseMult(d.Bytes())
	privateKey := ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: crypto.S256(),
			X:     pkX,
			Y:     pkY,
		},
		D: d,
	}

	return crypto.PubkeyToAddress(privateKey.PublicKey).String(), nil
}

// SavePrivateKey encrypts the private key with the given secret using AES
// and writes the encrypted output to the given io.Writer.
func SavePrivateKey(privKey *ecdsa.PrivateKey, secret []byte, out io.Writer) error {
	privKeyBytes := crypto.FromECDSA(privKey)
	if len(secret) == 0 {
		// writing plaintext
		_, err := out.Write(privKeyBytes)
		return errors.Wrap(err, "unable to write private key plaintext to writer")
	} else {
		// writing ciphertext
		ciphertext, err := encryptAes(privKeyBytes, secret)
		if err != nil {
			return errors.Wrap(err, "unable to encrypt private key")
		}
		_, err = out.Write(ciphertext)
		return errors.Wrap(err, "unable to write private key ciphertext to writer")
	}
}

// DecryptPrivateKey decrypts the encrypted private key read from the given
// io.Reader and writes the decrypted output (i.e the plaintext) to the given
// io.Writer.
func DecryptPrivateKey(in io.Reader, secret []byte, out io.Writer) error {
	ciphertext, err := ioutil.ReadAll(in)
	if err != nil {
		return errors.Wrap(err, "unable to read encrypted private key from reader")
	}

	plaintext, err := decryptAes(ciphertext, secret)
	if err != nil {
		return errors.Wrap(err, "unable to decrypt private key")
	}

	hexOut := make([]byte, hex.EncodedLen(len(plaintext)))
	hex.Encode(hexOut, plaintext)

	_, err = out.Write(hexOut)
	return errors.Wrap(err, "unable to write plaintext private key to writer")
}

func encryptAes(data, secret []byte) (ciphertext []byte, err error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create aes block cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create GCM")
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.Wrap(err, "could not generate nonce")
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decryptAes(ciphertext, secret []byte) (plaintext []byte, err error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create aes block cipher")
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, "unable to create GCM")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.Wrap(err, "unable to decrypt ciphertext")
	}
	return plaintext, nil
}

func DecodePublicKey(pubkey string) (*ecdsa.PublicKey, error) {
	pubBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}

	pubKey, err := crypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}
