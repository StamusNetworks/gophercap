/*
Copyright © 2020 Stamus Networks oss@stamus-networks.com

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
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gopherCap",
	Short: "Accurate, modular, scalable pcap manipulation tool written in Go.",
	Long: `Usage examples:

Map metadata for all gzipped PCAP files in a folder:
gopherCap map \
	--dir-src /mnt/data/pcaps/<...> \
	--file-suffix pcap.gz \
	--dump-json dump.json

Replay a subset of PCAP files from prevously mapped JSON dump to virtual interface:
sudo gopherCap replay \
	--dump-json dump.json \
	--out-interface veth1 \
	--file-regexp "190124-0000002\d+"

Extract pcaps from tar.gz that match a pattern. Write them to a directory in gzip format.
gopherCap tarExtract \
	--in-tarball /mnt/ext/pcap/big.tar.gz \
	--file-regexp 'owl-20012\d+-\d+\.pcap' \
	--out-dir /mnt/pcap --out-gzip

Each subcommand has separate --help. Please refer to that for more specific usage.
`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go-replay.yaml)")

	rootCmd.PersistentFlags().String("dump-json", "db/mapped-files.json",
		`Full or relative path for storing pcap metadata in JSON format.`)
	viper.BindPFlag("dump.json", rootCmd.PersistentFlags().Lookup("dump-json"))

	rootCmd.PersistentFlags().String("file-regexp", "",
		`Regex pattern to filter files.`)
	viper.BindPFlag("file.regexp", rootCmd.PersistentFlags().Lookup("file-regexp"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".go-replay" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".go-replay")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}
	logrus.SetLevel(logrus.DebugLevel)
}
