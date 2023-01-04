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
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/StamusNetworks/gophercap/pkg/dedup"
	"github.com/StamusNetworks/gophercap/pkg/filter"
	"github.com/StamusNetworks/gophercap/pkg/replay"
	"golang.org/x/sync/errgroup"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// filterCmd represents the filter command
var filterCmd = &cobra.Command{
	Use:   "filter",
	Short: "Filter is for concurrent packet extraction with many PCAPs and many BPF filters",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		workers := viper.GetInt("filter.workers")

		if workers < 1 {
			logrus.Fatalf("Invalid worker count: %d", workers)
		}

		input := viper.GetString("filter.input")
		if input == "" {
			logrus.Fatal(errors.New("Missing input folder"))
		}

		output := viper.GetString("filter.output")
		if output == "" {
			logrus.Fatal(errors.New("Missing output folder"))
		}

		filters := make(map[string]filter.Matcher)

		if configPath := viper.GetString("filter.yaml"); configPath != "" {
			var cfg filter.YAMLConfig
			data, err := os.ReadFile(viper.GetString("filter.yaml"))
			if err != nil {
				logrus.Fatalf("Filter input read: %s", err)
			}
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				logrus.Fatal(err)
			}
			for name, config := range cfg {
				m, err := filter.NewCombinedMatcher(filter.MatcherConfig{
					CombinedConfig: config,
					MaxMindASN:     viper.GetString("filter.maxmind.asn"),
				})
				if err != nil {
					logrus.Fatal(err)
				}
				filters[name] = m
				logrus.Infof("filter %s got %d conditions", name, len(m.Conditions))
			}
		} else {
			logrus.Warn("Filter config missing, running with empty set")
			filters["raw"] = filter.DummyMatcher{}
		}

		tasks := make(chan filter.Task, workers)

		ctx, cancel := context.WithCancel(context.Background())
		pool, ctx := errgroup.WithContext(ctx)
		for i := 0; i < workers; i++ {
			id := i
			pool.Go(func() error {
				logrus.Infof("Worker %d started", id)
				defer logrus.Infof("Worker %d done", id)
			loop:
				for {
					select {
					case <-ctx.Done():
						logrus.WithField("worker", id).Warn("early exit called")
						break loop
					case task, ok := <-tasks:
						if !ok {
							break loop
						}
						logrus.WithFields(logrus.Fields{
							"input":  task.Input,
							"output": filepath.Dir(task.Output),
							"desc":   task.Description,
						}).Info("Filtering file")
						result, err := filter.ReadAndFilter(&filter.Config{
							File: struct {
								Input  string
								Output string
							}{
								Input:  task.Input,
								Output: task.Output,
							},
							Filter:        task.Filter,
							Decapsulate:   viper.GetBool("filter.decap.enabled"),
							DecapMaxDepth: viper.GetInt("filter.decap.depth"),
							Compress:      viper.GetBool("filter.compress"),
							StatFunc: func(fr map[string]any) {
								logrus.WithField("worker", id).WithFields(fr).Debug("filter report")
							},
							Ctx: ctx,
							Dedup: func() dedup.Dedupper {
								if viper.GetBool("filter.dedup") {
									return dedup.NewCircularDedup(3, 2*time.Second)
								}
								return nil
							}(),
						})
						if err != nil {
							switch err.(type) {
							case filter.ErrEarlyExit:
								logrus.WithField("worker", id).Warn("early exit called")
								break loop
							default:
								logrus.Error(err)
							}
						}
						logrus.Infof("DONE: %+v", result)
					}
				}
				return nil
			})
		}

		chSIG := make(chan os.Signal, 1)
		signal.Notify(chSIG, os.Interrupt)

		go func(ctx context.Context) {
			<-chSIG
			cancel()
		}(context.TODO())

		files, err := replay.FindPcapFiles(input, viper.GetString("filter.suffix"))
		if err != nil {
			logrus.Fatalf("PCAP list gen: %s", err)
		}

	outer:
		for _, inFile := range files {
		inner:
			for name, matcher := range filters {
				outDir := filepath.Join(output, name)
				stat, err := os.Stat(outDir)
				if os.IsNotExist(err) {
					if err := os.Mkdir(outDir, 0750); err != nil {
						logrus.Fatal(err)
					}
				} else if !stat.IsDir() {
					logrus.Fatalf("Output path %s exists and is not a directory", output)
				}

				outFile := filter.ExtractBaseName(inFile) + ".pcap"
				outFile = filepath.Join(outDir, outFile)

				logrus.WithFields(logrus.Fields{
					"filter": name,
					"path":   outFile,
				}).Info("feeding file to matcher")

				select {
				case tasks <- filter.Task{
					Input:       inFile,
					Output:      outFile,
					Filter:      matcher,
					Description: name,
				}:
				case <-ctx.Done():
					break outer
					break inner
				}
			}
		}
		close(tasks)
		if err := pool.Wait(); err != nil {
			logrus.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(filterCmd)

	filterCmd.PersistentFlags().String("yaml", "",
		`Source file for BPF filters. `+
			`Format is YAML. Key is name of the filter which also translates to output folder. `+
			`Value is a list of networks. Packets matching those networks will be written to output file.`)
	viper.BindPFlag("filter.yaml", filterCmd.PersistentFlags().Lookup("yaml"))

	filterCmd.PersistentFlags().Int("workers", 4, `Number of PCAP files to be parsed at once.`)
	viper.BindPFlag("filter.workers", filterCmd.PersistentFlags().Lookup("workers"))

	filterCmd.PersistentFlags().String("input", "", `Input folder for filtered PCAP files.`)
	viper.BindPFlag("filter.input", filterCmd.PersistentFlags().Lookup("input"))

	filterCmd.PersistentFlags().String("output", "", `Output folder for filtered PCAP files.`)
	viper.BindPFlag("filter.output", filterCmd.PersistentFlags().Lookup("output"))

	filterCmd.PersistentFlags().Bool("decap", false, `Decapsulate GRE and ERSPAN headers.`)
	viper.BindPFlag("filter.decap.enabled", filterCmd.PersistentFlags().Lookup("decap"))

	filterCmd.PersistentFlags().Int("decap-depth", -1, `Max posterior packet layers to check for decap.`)
	viper.BindPFlag("filter.decap.depth", filterCmd.PersistentFlags().Lookup("decap-depth"))

	filterCmd.PersistentFlags().Bool("compress", false, `Write output packets directly to gzip stream.`)
	viper.BindPFlag("filter.compress", filterCmd.PersistentFlags().Lookup("compress"))

	filterCmd.PersistentFlags().Bool("dedup", false, `Apply best-effort software dedup.`)
	viper.BindPFlag("filter.dedup", filterCmd.PersistentFlags().Lookup("dedup"))

	filterCmd.PersistentFlags().String("maxmind-asn", "", `Path to maxmind ASN database. Only needed if ASN filter is used.`)
	viper.BindPFlag("filter.maxmind.asn", filterCmd.PersistentFlags().Lookup("maxmind-asn"))

	filterCmd.PersistentFlags().String("suffix", "pcap", "Find files with following suffix.")
	viper.BindPFlag("filter.suffix", filterCmd.PersistentFlags().Lookup("suffix"))
}
