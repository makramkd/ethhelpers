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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign/bls"
)

var blsCmd = &cobra.Command{
	Use:   "bls",
	Short: "Top level command for doing various bls operations (e.g generating key pair)",
	Long:  ``,
}

var genKeyPair = &cobra.Command{
	Use:   "genkeypair",
	Short: "Generate a new key pair amenable to BLS signatures",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		curve, err := cmd.Flags().GetString("curve")
		fatal(err)
		if curve != "bn256" {
			fatal(errors.New("only bn256 is supported"))
		}

		n, err := cmd.Flags().GetInt("n")
		fatal(err)
		if n < 1 {
			fatal(errors.New("n must be at least 1"))
		}

		suite := pairing.NewSuiteBn256()
		for i := 0; i < n; i++ {
			secretKey, pubKey := bls.NewKeyPair(suite, suite.RandomStream())
			pubBytes, err := pubKey.MarshalBinary()
			fatal(err)
			fmt.Printf("Secret key %d: %s\n", i+1, secretKey.String())
			fmt.Printf("Public key %d: %s\n", i+1, hex.EncodeToString(pubBytes))
		}
	},
}

var sign = &cobra.Command{
	Use:   "sign",
	Short: "Sign a message using BLS signatures",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		curve, err := cmd.Flags().GetString("curve")
		fatal(err)
		if curve != "bn256" {
			fatal(errors.New("only bn256 is supported"))
		}

		message, err := cmd.Flags().GetString("message")
		fatal(err)

		secretKeyHex, err := cmd.Flags().GetString("sk")
		fatal(err)

		secretKeyBytes, err := hex.DecodeString(secretKeyHex)
		fatal(err)

		suite := pairing.NewSuiteBn256()
		secretKey := suite.Scalar().Zero()
		err = secretKey.UnmarshalBinary(secretKeyBytes)
		fatal(err)

		sig, err := bls.Sign(suite, secretKey, []byte(message))
		fatal(err)

		fmt.Println("BLS signature: ", hex.EncodeToString(sig))
	},
}

var verify = &cobra.Command{
	Use:   "verify",
	Short: "Verify that a BLS signature is sound",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		curve, err := cmd.Flags().GetString("curve")
		fatal(err)
		if curve != "bn256" {
			fatal(errors.New("only bn256 is supported"))
		}

		message, err := cmd.Flags().GetString("message")
		fatal(err)
		if len(message) == 0 {
			fatal(errors.New("message must be non-empty"))
		}

		pubKeyHex, err := cmd.Flags().GetString("pubkey")
		fatal(err)
		pubKeyBytes, err := hex.DecodeString(pubKeyHex)
		fatal(err)

		sigHex, err := cmd.Flags().GetString("sig")
		fatal(err)
		sigBytes, err := hex.DecodeString(sigHex)
		fatal(err)

		suite := pairing.NewSuiteBn256()
		pubKey := suite.Point()
		err = pubKey.UnmarshalBinary(pubKeyBytes)
		fatal(err)

		err = bls.Verify(suite, pubKey, []byte(message), sigBytes)
		fatal(err)

		fmt.Println("signature is valid!")
	},
}

var aggregate = &cobra.Command{
	Use:   "aggregate",
	Short: "Aggregate many signatures (of distinct messages) into a single signature",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		curve, err := cmd.Flags().GetString("curve")
		fatal(err)
		if curve != "bn256" {
			fatal(errors.New("only bn256 is supported"))
		}

		sigsHex, err := cmd.Flags().GetStringSlice("sigs")
		fatal(err)

		var sigsBytes [][]byte
		for _, sigHex := range sigsHex {
			sigBytes, err := hex.DecodeString(sigHex)
			fatal(err)
			sigsBytes = append(sigsBytes, sigBytes)
		}

		suite := pairing.NewSuiteBn256()
		aggSig, err := bls.AggregateSignatures(suite, sigsBytes...)
		fatal(err)

		fmt.Println("Aggregated signature:", hex.EncodeToString(aggSig))
	},
}

var batchVerify = &cobra.Command{
	Use:   "batchverify",
	Short: "Verify an aggregated BLS signature",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		curve, err := cmd.Flags().GetString("curve")
		fatal(err)
		if curve != "bn256" {
			fatal(errors.New("only bn256 is supported"))
		}

		aggSigHex, err := cmd.Flags().GetString("aggsig")
		fatal(err)

		if len(aggSigHex) == 0 {
			fatal(errors.New("must provide valid aggregated signature"))
		}

		aggSigBytes, err := hex.DecodeString(aggSigHex)
		fatal(err)

		suite := pairing.NewSuiteBn256()

		pubKeysHex, err := cmd.Flags().GetStringSlice("pubkeys")
		fatal(err)

		var pubKeys []kyber.Point
		for _, pubKeyHex := range pubKeysHex {
			pubKeyBytes, err := hex.DecodeString(pubKeyHex)
			fatal(err)
			pubKey := suite.Point()
			err = pubKey.UnmarshalBinary(pubKeyBytes)
			fatal(err)
			pubKeys = append(pubKeys, pubKey)
		}

		messages, err := cmd.Flags().GetStringSlice("messages")
		fatal(err)

		var messagesBytes [][]byte
		for _, message := range messages {
			messagesBytes = append(messagesBytes, []byte(message))
		}

		err = bls.BatchVerify(suite, pubKeys, messagesBytes, aggSigBytes)
		fatal(err)
		fmt.Println("batch signature is valid!")
	},
}

func setupBlsCommand() {
	genKeyPair.Flags().String("curve", "bn256", "Which pairing curve to use")
	genKeyPair.Flags().Int("n", 1, "How many key pairs to create")

	sign.Flags().String("curve", "bn256", "Which pairing curve to use")
	sign.Flags().String("message", "", "The message to sign")
	sign.Flags().String("sk", "", "The secret key to sign with")

	verify.Flags().String("curve", "bn256", "Which pairing curve to use")
	verify.Flags().String("message", "", "The message to sign")
	verify.Flags().String("pubkey", "", "The public key associated with the private key that signed the message")
	verify.Flags().String("sig", "", "The BLS signature to verify")

	aggregate.Flags().String("curve", "bn256", "Which pairing curve to use")
	aggregate.Flags().StringSlice("sigs", nil, "The signatures to aggregate")

	batchVerify.Flags().String("curve", "bn256", "Which pairing curve to use")
	batchVerify.Flags().String("aggsig", "", "The aggregated signature to verify")
	batchVerify.Flags().StringSlice("pubkeys", nil, "The public keys corresponding to the private keys that the aggregated signature is signed by")
	batchVerify.Flags().StringSlice("messages", nil, "The messages signed by each individual signature in the aggregate. These must be distinct.")

	blsCmd.AddCommand(genKeyPair)
	blsCmd.AddCommand(sign)
	blsCmd.AddCommand(verify)
	blsCmd.AddCommand(aggregate)
	blsCmd.AddCommand(batchVerify)

	rootCmd.AddCommand(blsCmd)
}
