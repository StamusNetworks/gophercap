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
	"context"
	"regexp"
	"time"

	"gopherCap/pkg/pcapset"
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
		set, err := pcapset.LoadSetJSON(viper.GetString("dump.json"))
		if err != nil {
			logrus.Fatal(err)
		}
		iterations := viper.GetInt("loop.count")
		if iterations < 1 || viper.GetBool("loop.infinite") {
			logrus.Infof("Negative iteration count or --loop-infinite called. Enabling infinite loop.")
		}
		var count int
	loop:
		for {
			count++
			if !viper.GetBool("loop.infinite") && count > iterations {
				if iterations > 1 {
					logrus.Infof("Max iteration count %d reached. Stopping loop.", iterations)
				}
				break loop
			}
			logrus.Infof("Starting iteration %d", count)
			handle, err := replay.NewHandle(replay.Config{
				Set:            *set,
				WriteInterface: viper.GetString("out.interface"),
				FilterRegex: func() *regexp.Regexp {
					if pattern := viper.GetString("file.regexp"); pattern != "" {
						re, err := regexp.Compile(pattern)
						if err != nil {
							logrus.Fatal(err)
						}
						return re
					}
					return nil
				}(),
				SpeedModifier: func() float64 {
					if viper.GetBool("time.scale.enabled") {
						dur := viper.GetDuration("time.scale.duration")
						mod := float64(set.Duration()) / float64(dur)
						logrus.Infof("Timescaling enabled with duration %s. Set duration is %s. Using modifier %.2f",
							dur, set.Duration(), mod)
						return mod
					}
					return viper.GetFloat64("time.modifier")
				}(),
				TimeFrom: func() time.Time {
					if from := viper.GetString("time.from"); from != "" {
						ts, err := time.Parse(argTsFormat, from)
						if err != nil {
							logrus.Fatalf("Invalid timestamp %s, please follow this format: %s",
								from, argTsFormat)
						}
						return ts.UTC()
					}
					return time.Time{}
				}(),
				TimeTo: func() time.Time {
					if from := viper.GetString("time.to"); from != "" {
						ts, err := time.Parse(argTsFormat, from)
						if err != nil {
							logrus.Fatalf("Invalid timestamp %s, please follow this format: %s",
								from, argTsFormat)
						}
						return ts.UTC()
					}
					return time.Time{}
				}(),
				OutBpf:      viper.GetString("out.bpf"),
				DisableWait: viper.GetBool("wait.disable"),
			})
			if err != nil {
				logrus.Fatal(err)
			}
			go func() {
				for err := range handle.Errors() {
					logrus.Error(err)
				}
			}()
			logrus.Debugf(
				"Global set period is %s ->>> %s",
				handle.FileSet.Period.Beginning,
				handle.FileSet.Period.End,
			)
			for _, f := range handle.FileSet.Files {
				logrus.Debugf("File %s in replay set beginning %s end %s", f.Path, f.Beginning, f.End)
			}
			start := time.Now()
			if err := handle.Play(context.TODO()); err != nil {
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
	viper.BindPFlag("out.interface", replayCmd.PersistentFlags().Lookup("out-interface"))

	replayCmd.PersistentFlags().String("out-bpf", "",
		`BPF filter to exclude some packets.`)
	viper.BindPFlag("out.bpf", replayCmd.PersistentFlags().Lookup("out-bpf"))

	replayCmd.PersistentFlags().Bool("loop-infinite", false,
		`Loop over pcap files infinitely. Will override --loop-count`)
	viper.BindPFlag("loop.infinite", replayCmd.PersistentFlags().Lookup("loop-infinite"))

	replayCmd.PersistentFlags().Int("loop-count", 1,
		`Number of iterations over pcap set. Will run infinitely if 0 or negative value is given.`)
	viper.BindPFlag("loop.count", replayCmd.PersistentFlags().Lookup("loop-count"))

	replayCmd.PersistentFlags().Float64("time-modifier", 1.0,
		`Modifier for speeding up or slowing down the replay by a factor of X.`)
	viper.BindPFlag("time.modifier", replayCmd.PersistentFlags().Lookup("time-modifier"))

	replayCmd.PersistentFlags().Duration("time-scale-duration", 1*time.Hour,
		`Duration for time scaling.`)
	viper.BindPFlag("time.scale.duration", replayCmd.PersistentFlags().Lookup("time-scale-duration"))

	replayCmd.Flags().String(
		"time-from", "", `Start replay from this time.`)
	viper.BindPFlag("time.from", replayCmd.Flags().Lookup("time-from"))

	replayCmd.Flags().String(
		"time-to", "", `End replay from this time.`)
	viper.BindPFlag("time.to", replayCmd.Flags().Lookup("time-to"))

	replayCmd.PersistentFlags().Bool("time-scale-enabled", false,
		`Enable time scaling. `+
			`When enabled, will automatically calculate time.modifier value to replay pcap in specified time window. `+
			`Overrides time.modifier value. Actual replay is not guaranteed to complete in defined time, `+
			`As overhead from sleep calculations causes a natural drift.`)
	viper.BindPFlag("time.scale.enabled", replayCmd.PersistentFlags().Lookup("time-scale-enabled"))

	replayCmd.PersistentFlags().Bool("wait-disable", false,
		`Disable initial wait before each PCAP file read. `+
			`Useful when PCAPs are part of same logical set but not from same capture period.`)
	viper.BindPFlag("wait.disable", replayCmd.PersistentFlags().Lookup("wait-disable"))
}
