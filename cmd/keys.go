/*
Copyright © 2021 Makram Kamaleddine

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/makramkd/ethhelpers/lib"
)

// keys represents the gen-key-pair command
var keys = &cobra.Command{
	Use:   "keys",
	Short: "Top level command for doing various key-related operations (e.g generating key pairs, decrypting keys, etc.)",
	Long:  ``,
	Run:   func(cmd *cobra.Command, args []string) {},
}

var generate = &cobra.Command{
	Use:   "generate",
	Short: "Generate a private/public keypair for use in one of Ethereum's networks.",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("printing args")
		pubOut, err := cmd.Flags().GetString("pub-out")
		fatal(err)
		privOut, err := cmd.Flags().GetString("priv-out")
		fatal(err)

		key, _ := cmd.Flags().GetString("key")
		if key == "" {
			log.Println("WARNING: no encryption key given. Private key will be saved as plaintext!")
		}

		privKey, pubKey, err := lib.GenPair()
		fatal(err)

		addressFile, err := os.Create(pubOut)
		fatal(err)
		defer addressFile.Close()

		err = lib.SaveAddress(pubKey, addressFile)
		fatal(err)

		privFile, err := os.Create(privOut)
		fatal(err)
		defer privFile.Close()

		err = lib.SavePrivateKey(privKey, []byte(key), privFile)
		fatal(err)

		log.Println("done!")
	},
}

var decrypt = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt a file containing a private key.",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		key, err := cmd.Flags().GetString("key")
		fatal(err)
		if key == "" {
			log.Fatal("key must not be empty")
		}

		privFilename, err := cmd.Flags().GetString("priv")
		fatal(err)

		outFilename, err := cmd.Flags().GetString("out")
		fatal(err)

		privCipher, err := os.Open(privFilename)
		fatal(err)
		defer privCipher.Close()

		outFile, err := os.Create(outFilename)
		fatal(err)
		defer outFile.Close()

		fatal(lib.DecryptPrivateKey(privCipher, []byte(key), outFile))

		log.Println("done!")
	},
}

var getAddress = &cobra.Command{
	Use:   "get-address",
	Short: "Get the address associated with the given private key",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		key, err := cmd.Flags().GetString("pkey")
		fatal(err)
		if key == "" {
			log.Fatal("key must not be empty")
		}

		address, err := lib.GetAddress(key)
		fatal(err)

		log.Println("Address: ", address)
	},
}

func setupKeysCommand() {
	rootCmd.AddCommand(keys)

	keys.AddCommand(generate)
	keys.AddCommand(decrypt)
	keys.AddCommand(getAddress)

	generate.Flags().StringP("pub-out", "p", "pubkey.txt", "Text file to write public key to")
	generate.Flags().StringP("priv-out", "s", "secretkey.bin", "Binary file to write private key to")
	generate.Flags().StringP("key", "k", "", "Encryption key to encrypt the private key. Leave empty for no encryption.")

	decrypt.Flags().StringP("key", "k", "", "Encryption key that was used to encrypt the file.")
	decrypt.Flags().StringP("priv", "s", "secretkey.bin", "Binary file containing encrypted private key")
	decrypt.Flags().StringP("out", "o", "secretkey.txt", "Text file that will contain plaintext private key")

	getAddress.Flags().StringP("pkey", "k", "", "Private key to get address for")
}

func init() {
	setupKeysCommand()
	setupAbiCommand()
}
