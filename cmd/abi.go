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
