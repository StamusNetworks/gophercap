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
	"gopherCap/pkg/fs"
	"gopherCap/pkg/pcapset"

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
		files, err := fs.NewPcapList(
			viper.GetString("dir.src"),
			viper.GetString("file.suffix"),
		)
		if err != nil {
			logrus.Fatal(err)
		}

		set, err := pcapset.NewPcapSetFromList(
			files,
			func() int {
				if workers := viper.GetInt("file.workers"); workers > 0 {
					logrus.Infof("Using %d workers for mapping", workers)
					return workers
				}
				return len(files)
			}(),
			viper.GetString("file.regexp"),
		)

		if err != nil {
			logrus.Fatal(err)
		}

		for _, f := range set.Files {
			if f.Err != nil {
				logrus.Errorf("%s encountered error: %s", f.Path, f.Err)
			} else {
				logrus.Infof("%s -> %s ||| %d packets ||| %d bytes ||| %s",
					f.Period.Beginning, f.Period.End, f.Counters.Packets, f.Counters.Size, f.Path)
			}
		}
		if removed, err := set.FilterFilesWithErrs(); err != nil {
			logrus.Fatal(err)
		} else if removed > 0 {
			logrus.Warnf("Unable to map %d files, removing from final dump.", removed)
		}
		logrus.Infof("Dumping %d pcap file info between %s and %s to %s.",
			len(set.Files), set.Beginning, set.End, viper.GetString("dump.json"))

		if err := pcapset.DumpSetJSON(viper.GetString("dump.json"), *set); err != nil {
			logrus.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(mapCmd)

	mapCmd.PersistentFlags().String("dir-src", "",
		`Source folder for recursive pcap search.`)
	viper.BindPFlag("dir.src", mapCmd.PersistentFlags().Lookup("dir-src"))

	mapCmd.PersistentFlags().String("file-suffix", "pcap.gz",
		`Suffix suffix used for file discovery.`)
	viper.BindPFlag("file.suffix", mapCmd.PersistentFlags().Lookup("file-suffix"))

	mapCmd.PersistentFlags().Int("file-workers", 4,
		`Number of concurrent workers for scanning pcap files. `+
			`Value less than 1 will map all pcap files concurrently.`)
	viper.BindPFlag("file.workers", mapCmd.PersistentFlags().Lookup("file-workers"))
}
