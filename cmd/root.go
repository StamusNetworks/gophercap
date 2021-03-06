/*
Copyright © 2020 Stamus Networks oss@stamus-networks.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
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

	rootCmd.PersistentFlags().String("dump-json", "/tmp/mapped-files.json",
		`Full or relative path for storing pcap metadata in JSON format.`)
	viper.BindPFlag("global.dump.json", rootCmd.PersistentFlags().Lookup("dump-json"))

	rootCmd.PersistentFlags().String("file-regexp", "",
		`Regex pattern to filter files.`)
	viper.BindPFlag("global.file.regexp", rootCmd.PersistentFlags().Lookup("file-regexp"))
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
