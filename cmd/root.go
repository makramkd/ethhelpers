/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

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
	"github.com/spf13/cobra/doc"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "ethhelpers",
	Short: "A collection of misc utilities that could be helpful in blockchain and cryptography development",
	Long: `
ethhelpers contains some utilities that have come up useful in blockchain and cryptography development.

Execute 'ethhelpers help' to see all the available commands.
	`,
}

var docCmd = &cobra.Command{
	Use:   "doc",
	Short: "Generate documentation for ethhelpers",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		outPath, err := cmd.Flags().GetString("o")
		fatal(err)
		if _, err := os.Stat(outPath); os.IsNotExist(err) {
			fatal(fmt.Errorf("Given path %s does not exist: %w", outPath, err))
		}

		err = doc.GenMarkdownTree(rootCmd, outPath)
		fatal(err)
		fmt.Println("docs generated!")
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.ethhelpers.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".ethhelpers" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".ethhelpers")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func init() {
	docCmd.Flags().String("o", "doc", "Output path of ethhelpers Markdown documentation.")

	rootCmd.AddCommand(docCmd)

	setupKeysCommand()
	setupAbiCommand()
	setupBlsCommand()
}
