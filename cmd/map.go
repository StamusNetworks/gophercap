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
	"github.com/StamusNetworks/gophercap/pkg/replay"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// mapCmd represents the map command
var mapCmd = &cobra.Command{
	Use:   "map",
	Short: "Parse PCAP files for metadata mapping.",
	Long: `Recursively discovers all PCAP files in directory matching user-defined name pattern.  First and last timestamp of each pcap file is parsed and stored in JSON dump.  Also calculates additional metadata, such as data size in bytes, packets, PPS, etc.  All files are processed in parallel, as we iterate over entire pcap file. Output dump is then loaded into replay step to save time.

Example usage:
gopherCap map \
	--dir-src /mnt/pcap \
	--file-suffix "pcap" \
	--dump-json /mnt/pcap/meta.json
`,
	Run: func(cmd *cobra.Command, args []string) {
		set, err := replay.NewPcapSet(replay.MapConfig{
			Directory: viper.GetString("map.dir.src"),
			Suffix:    viper.GetString("map.file.suffix"),
			Workers:   viper.GetInt("map.file.workers"),
			Pattern:   viper.GetString("global.file.regexp"),
		})
		if err != nil {
			logrus.Fatal(err)
		}

		if err := replay.DumpSetJSON(viper.GetString("global.dump.json"), *set); err != nil {
			logrus.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(mapCmd)

	mapCmd.PersistentFlags().String("dir-src", "",
		`Source folder for recursive pcap search.`)
	viper.BindPFlag("map.dir.src", mapCmd.PersistentFlags().Lookup("dir-src"))

	mapCmd.PersistentFlags().String("file-suffix", "pcap",
		`Suffix suffix used for file discovery.`)
	viper.BindPFlag("map.file.suffix", mapCmd.PersistentFlags().Lookup("file-suffix"))

	mapCmd.PersistentFlags().Int("file-workers", 4,
		`Number of concurrent workers for scanning pcap files. `+
			`Value less than 1 will map all pcap files concurrently.`)
	viper.BindPFlag("map.file.workers", mapCmd.PersistentFlags().Lookup("file-workers"))
}
