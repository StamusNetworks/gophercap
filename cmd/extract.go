/*
Copyright © 2021 Stamus Networks oss@stamus-networks.com

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
	"gopherCap/pkg/extract"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract data for a single flow from Suricata pcap directory.",
	Long: `Generate a pcap for a single flow specified in a Suricata event.

Example usage:
gopherCap extract \
	--dir-pcap /var/log/suricata \
	--event /tmp/event.json \
	--dump-pcap /tmp/event.pcap \
	--file-format log-%n-%t.pcap \
	--skip-bpf
`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := extract.ExtractPcapFile(viper.GetString("extract.dir.pcap"),
			viper.GetString("extract.dump.pcap"), viper.GetString("extract.event"),
			viper.GetBool("extract.skip.bpf"), viper.GetString("extract.file.format")); err != nil {
			logrus.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(extractCmd)

	extractCmd.PersistentFlags().String("dir-pcap", "",
		`Source folder for pcap search.`)
	viper.BindPFlag("extract.dir.pcap", extractCmd.PersistentFlags().Lookup("dir-pcap"))
	extractCmd.PersistentFlags().String("event", "",
		`Event to get flow info from.`)
	viper.BindPFlag("extract.event", extractCmd.PersistentFlags().Lookup("event"))
	extractCmd.PersistentFlags().String("dump-pcap", "",
		`Pcap file to extract data to.`)
	viper.BindPFlag("extract.dump.pcap", extractCmd.PersistentFlags().Lookup("dump-pcap"))
	extractCmd.PersistentFlags().Bool("skip-bpf", false,
		`Explicitely extract data with gopacket parsing. Slower but more accurate.`)
	viper.BindPFlag("extract.skip.bpf", extractCmd.PersistentFlags().Lookup("skip-bpf"))
	extractCmd.PersistentFlags().String("file-format", "pcap.%n.%t",
		`How pcap files are named by Suricata.`)
	viper.BindPFlag("extract.file.format", extractCmd.PersistentFlags().Lookup("file-format"))
}
