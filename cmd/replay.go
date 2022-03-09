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
	"context"
	"regexp"
	"time"

	"gopherCap/pkg/replay"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const argTsFormat = "2006-01-02 15:04:05"

// replayCmd represents the replay command
var replayCmd = &cobra.Command{
	Use:   "replay",
	Short: "Replay pcap files while preserving temporal properties.",
	Long: `Load metadata for PCAP dataset and replay them into a network interface
while perserving time diffs between each packet. All readers are started in parallel, 
but each will sleep for a calculated duration between pcap start and global dataset
start. Thus handling datasets where tool like Moloch wrote multiple pcap files in parallel, but not info exists any more on which thread corresponds to which pcap.

Example usage:
gopherCap replay \
	--out-interface veth0 \
	--dump-json /mnt/pcap/meta.json

Usage with pcap timestamp and written packet filtering:
gopherCap replay \
	--out-interface veth0 \
	--dump-json "db/mapped-files.json"
	--file-regexp '200928+-\d+' \
	--time-from "2020-09-28 06:00:00" \
	--time-to "2020-09-28 16:00:00" \
	--out-bpf "not net 10.0.0.0/32"

Usage timescaling to replay 1 day pcap set (approximately) in 4 hours:
gopherCap replay \
	--out-interface veth0 \
	--dump-json "db/mapped-files.json"
	--file-regexp '200928+-\d+' \
	--time-scale-enabled \
	--time-scale-duration 4h

Set up virtual ethernet interface for testing or local capture:
sudo ip link add veth0 type veth peer name veth1

sudo ip link set dev veth0 mtu 9000
sudo ip link set dev veth1 mtu 9000

sudo ip link set veth0 up
sudo ip link set veth1 up

Increase interface MTU if you get this error:
FATA[0005] send: Message too long
`,
	Run: func(cmd *cobra.Command, args []string) {
		set, err := replay.LoadSetJSON(viper.GetString("global.dump.json"))
		if err != nil {
			logrus.Fatal(err)
		}
		iterations := viper.GetInt("replay.loop.count")
		if iterations < 1 || viper.GetBool("replay.loop.infinite") {
			logrus.Infof("Negative iteration count or --loop-infinite called. Enabling infinite loop.")
		}
		var count int
	loop:
		for {
			count++
			if !viper.GetBool("replay.loop.infinite") && count > iterations {
				if iterations > 1 {
					logrus.Infof("Max iteration count %d reached. Stopping loop.", iterations)
				}
				break loop
			}
			logrus.Infof("Starting iteration %d", count)
			handle, err := replay.NewHandle(replay.Config{
				Set:            *set,
				Ctx:            context.Background(),
				WriteInterface: viper.GetString("replay.out.interface"),
				ScaleDuration:  viper.GetDuration("replay.time.scale.duration"),
				ScaleEnabled:   viper.GetBool("replay.time.scale.enabled"),
				ScalePerFile:   viper.GetBool("replay.disable_wait"),
				OutBpf:         viper.GetString("replay.out.bpf"),
				DisableWait:    viper.GetBool("replay.disable_wait"),
				SkipOutOfOrder: viper.GetBool("replay.skip.out_of_order"),
				SkipMTU:        viper.GetInt("replay.skip.mtu"),
				Reorder:        viper.GetBool("replay.reorder.enabled"),
				FilterRegex: func() *regexp.Regexp {
					if pattern := viper.GetString("global.file.regexp"); pattern != "" {
						re, err := regexp.Compile(pattern)
						if err != nil {
							logrus.Fatal(err)
						}
						return re
					}
					return nil
				}(),
				TimeFrom: func() time.Time {
					if from := viper.GetString("replay.time.from"); from != "" {
						ts, err := time.Parse(argTsFormat, from)
						if err != nil {
							logrus.Fatalf("Invalid timestamp %s, please follow this format: %s", from, argTsFormat)
						}
						return ts.UTC()
					}
					return time.Time{}
				}(),
				TimeTo: func() time.Time {
					if from := viper.GetString("replay.time.to"); from != "" {
						ts, err := time.Parse(argTsFormat, from)
						if err != nil {
							logrus.Fatalf("Invalid timestamp %s, please follow this format: %s", from, argTsFormat)
						}
						return ts.UTC()
					}
					return time.Time{}
				}(),
			})
			if err != nil {
				logrus.Fatal(err)
			}
			logrus.WithFields(logrus.Fields{
				"beginning": handle.FileSet.Beginning,
				"end":       handle.FileSet.End,
			}).Info("PCAP set loaded")
			start := time.Now()
			if err := handle.Play(); err != nil {
				logrus.Fatal(err)
			}
			logrus.Infof("Iteration %d done in %s.", count, time.Since(start))
		}
	},
}

func init() {
	rootCmd.AddCommand(replayCmd)

	replayCmd.PersistentFlags().String("out-interface", "eth0",
		`Network interface to replay to.`)
	viper.BindPFlag("replay.out.interface", replayCmd.PersistentFlags().Lookup("out-interface"))

	replayCmd.PersistentFlags().String("out-bpf", "",
		`BPF filter to exclude some packets.`)
	viper.BindPFlag("replay.out.bpf", replayCmd.PersistentFlags().Lookup("out-bpf"))

	replayCmd.PersistentFlags().Bool("loop-infinite", false,
		`Loop over pcap files infinitely. Will override --loop-count`)
	viper.BindPFlag("replay.loop.infinite", replayCmd.PersistentFlags().Lookup("loop-infinite"))

	replayCmd.PersistentFlags().Int("loop-count", 1,
		`Number of iterations over pcap set. Will run infinitely if 0 or negative value is given.`)
	viper.BindPFlag("replay.loop.count", replayCmd.PersistentFlags().Lookup("loop-count"))

	replayCmd.Flags().String(
		"time-from", "", `Start replay from this time.`)
	viper.BindPFlag("replay.time.from", replayCmd.Flags().Lookup("time-from"))

	replayCmd.Flags().String(
		"time-to", "", `End replay from this time.`)
	viper.BindPFlag("replay.time.to", replayCmd.Flags().Lookup("time-to"))

	replayCmd.PersistentFlags().Bool("time-scale-enabled", false,
		`Enable time scaling. `+
			`Actual replay is not guaranteed to complete in defined time, `+
			`As overhead from sleep calculations causes a natural drift.`)
	viper.BindPFlag("replay.time.scale.enabled", replayCmd.PersistentFlags().Lookup("time-scale-enabled"))

	replayCmd.PersistentFlags().Duration("time-scale-duration", 1*time.Hour,
		`Duration for time scaling.`)
	viper.BindPFlag("replay.time.scale.duration", replayCmd.PersistentFlags().Lookup("time-scale-duration"))

	replayCmd.PersistentFlags().Bool("wait-disable", false,
		`Disable initial wait before each PCAP file read. `+
			`Useful when PCAPs are part of same logical set but not from same capture period.`)
	viper.BindPFlag("replay.disable_wait", replayCmd.PersistentFlags().Lookup("wait-disable"))

	replayCmd.PersistentFlags().Bool("skip-ooo", false, "Skip out of order packets. If disabled, out of order packets will be written with no delay.")
	viper.BindPFlag("replay.skip.out_of_order", replayCmd.PersistentFlags().Lookup("skip-ooo"))

	replayCmd.PersistentFlags().Int("skip-mtu", 1514, "Packets with total size in bytes bigger than this value will be dropped.")
	viper.BindPFlag("replay.skip.mtu", replayCmd.PersistentFlags().Lookup("skip-mtu"))

	replayCmd.PersistentFlags().Bool("reorder", false, "Enable packet reordering by timestamp. Adds overhead but is useful with out of order packets.")
	viper.BindPFlag("replay.reorder.enabled", replayCmd.PersistentFlags().Lookup("reorder"))
}
