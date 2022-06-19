package cmd

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
)

var ssCmd = &cobra.Command{
	Use:   "ss",
	Short: "Top level command for doing secret sharing operations",
}

var ssNewSecret = &cobra.Command{
	Use:   "new",
	Short: "Encode a secret in the binary representation expected by newpoly",
	Run: func(cmd *cobra.Command, args []string) {
		suiteName, err := cmd.Flags().GetString("suite")
		fatal(err)
		suite, err := suites.Find(suiteName)
		fatal(err)

		scalar := suite.Scalar().Pick(suite.RandomStream())
		scalarBytes, err := scalar.MarshalBinary()
		fatal(err)
		fmt.Println("Secret:", hex.EncodeToString(scalarBytes))
	},
}

var ssNewPoly = &cobra.Command{
	Use:   "newpoly",
	Short: "Generate a new private polynomial for the provided secret and print the private and public shares",
	Run: func(cmd *cobra.Command, args []string) {
		suiteName, err := cmd.Flags().GetString("suite")
		fatal(err)
		suite, err := suites.Find(suiteName)
		fatal(err)

		threshold, err := cmd.Flags().GetInt("threshold")
		fatal(err)

		numShares, err := cmd.Flags().GetInt("numshares")
		fatal(err)

		secretHex, err := cmd.Flags().GetString("secret")
		fatal(err)

		secretBytes, err := hex.DecodeString(secretHex)
		fatal(err)

		secretScalar := suite.Scalar()
		fatal(secretScalar.UnmarshalBinary(secretBytes))

		privPoly := share.NewPriPoly(suite, threshold, secretScalar, suite.RandomStream())
		privShares := privPoly.Shares(numShares)
		for _, pShare := range privShares {
			vBytes, err := pShare.V.MarshalBinary()
			fatal(err)

			fmt.Println("priv share index:", pShare.I, "share val:", hex.EncodeToString(vBytes))
		}

		pubPoly := privPoly.Commit(nil)
		pubShares := pubPoly.Shares(numShares)

		for _, pShare := range pubShares {
			vBytes, err := pShare.V.MarshalBinary()
			fatal(err)

			fmt.Println("pub share index:", pShare.I, "share val:", hex.EncodeToString(vBytes))
		}

		fmt.Println("secret commitment:", pubPoly.Commit())
	},
}

var ssRecoverPublic = &cobra.Command{
	Use:   "recoverpub",
	Short: "Recover the shared secret commitment from public commitments",
	Run: func(cmd *cobra.Command, args []string) {
		suiteName, err := cmd.Flags().GetString("suite")
		fatal(err)
		suite, err := suites.Find(suiteName)
		fatal(err)

		threshold, err := cmd.Flags().GetInt("threshold")
		fatal(err)

		numShares, err := cmd.Flags().GetInt("numshares")
		fatal(err)

		sharesHex, err := cmd.Flags().GetStringSlice("shares")
		fatal(err)

		indexes, err := cmd.Flags().GetIntSlice("indexes")
		fatal(err)

		if len(sharesHex) != len(indexes) {
			panic("len of shares must equal len of indexes")
		}

		var shares []*share.PubShare
		for i, shareHex := range sharesHex {
			shareBytes, err := hex.DecodeString(shareHex)
			fatal(err)

			sharePoint := suite.Point()
			fatal(sharePoint.UnmarshalBinary(shareBytes))

			shares = append(shares, &share.PubShare{
				I: indexes[i],
				V: sharePoint,
			})
		}

		secretCommit, err := share.RecoverCommit(suite, shares, threshold, numShares)
		fatal(err)

		fmt.Println("Secret commit:", secretCommit.String())
	},
}

var ssRecoverSecret = &cobra.Command{
	Use:   "recover",
	Short: "Recover the shared secret from private secret shares",
	Run: func(cmd *cobra.Command, args []string) {
		suiteName, err := cmd.Flags().GetString("suite")
		fatal(err)
		suite, err := suites.Find(suiteName)
		fatal(err)

		threshold, err := cmd.Flags().GetInt("threshold")
		fatal(err)

		numShares, err := cmd.Flags().GetInt("numshares")
		fatal(err)

		sharesHex, err := cmd.Flags().GetStringSlice("shares")
		fatal(err)

		indexes, err := cmd.Flags().GetIntSlice("indexes")
		fatal(err)

		if len(sharesHex) != len(indexes) {
			panic("len of shares must equal len of indexes")
		}

		var shares []*share.PriShare
		for i, shareHex := range sharesHex {
			shareBytes, err := hex.DecodeString(shareHex)
			fatal(err)

			shareCoeff := suite.Scalar()
			fatal(shareCoeff.UnmarshalBinary(shareBytes))

			shares = append(shares, &share.PriShare{
				I: indexes[i],
				V: shareCoeff,
			})
		}

		secret, err := share.RecoverSecret(suite, shares, threshold, numShares)
		fatal(err)

		fmt.Println("shared secret:", secret.String())
	},
}

func setupSSCommand() {
	ssNewSecret.Flags().String("suite", "", "which cryptographic suite to use")

	ssNewPoly.Flags().String("secret", "", "the secret to be shared in hex")
	ssNewPoly.Flags().String("suite", "", "which cryptographic suite to use")
	ssNewPoly.Flags().Int("threshold", 0, "threshold for the secret sharing scheme")
	ssNewPoly.Flags().Int("numshares", 0, "number of shares to generate")

	ssRecoverPublic.Flags().String("suite", "", "which cryptographic suite to use")
	ssRecoverPublic.Flags().StringSlice("shares", nil, "public share values")
	ssRecoverPublic.Flags().IntSlice("indexes", nil, "public share indexes")
	ssRecoverPublic.Flags().Int("threshold", 0, "threshold for the secret sharing scheme")
	ssRecoverPublic.Flags().Int("numshares", 0, "number of shares generated")

	ssRecoverSecret.Flags().String("suite", "", "which cryptographic suite to use")
	ssRecoverSecret.Flags().StringSlice("shares", nil, "private share values")
	ssRecoverSecret.Flags().IntSlice("indexes", nil, "private share indexes")
	ssRecoverSecret.Flags().Int("threshold", 0, "threshold for the secret sharing scheme")
	ssRecoverSecret.Flags().Int("numshares", 0, "number of shares generated")

	ssCmd.AddCommand(ssNewSecret)
	ssCmd.AddCommand(ssNewPoly)
	ssCmd.AddCommand(ssRecoverSecret)
	ssCmd.AddCommand(ssRecoverPublic)

	rootCmd.AddCommand(ssCmd)
}
