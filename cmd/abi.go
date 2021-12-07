package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/makramkd/ethhelpers/lib"
	"github.com/spf13/cobra"
)

// abi represents the abi command family
var abi = &cobra.Command{
	Use:   "abi",
	Short: "Top level command for doing various abi operations (e.g encoding/decoding abi methods etc.)",
	Long:  ``,
}

var decode = &cobra.Command{
	Use:   "decode",
	Short: "Decode the given abi-encoded transaction inputs into human readable values",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		abiJSON, err := cmd.Flags().GetString("abijson")
		fatal(err)

		abiFile, err := os.Open(abiJSON)
		fatal(err)

		txInput, err := cmd.Flags().GetString("txinput")
		fatal(err)

		decoded, err := lib.DecodeABI(txInput, abiFile)
		fatal(err)

		for key, val := range decoded {
			fmt.Printf("%s -> %+v\n", key, val)
		}
	},
}

var encode = &cobra.Command{
	Use:   "encode",
	Short: "Encode the given function call using the given abi",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		log.Fatal("not implemented")
	},
}

func setupAbiCommand() {
	rootCmd.AddCommand(abi)
	abi.AddCommand(decode)
	abi.AddCommand(encode)

	decode.Flags().StringP("abijson", "j", "", "Path to the ABI JSON file to be used")
	decode.Flags().StringP("txinput", "i", "", "The abi-encoded transaction input to decode")
}
