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
	"errors"
	"fmt"
	"gopherCap/pkg/filter"
	"gopherCap/pkg/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

		// YAML filter input where key is filter name and value is list of networks
		f, err := os.Open(viper.GetString("filter.yaml"))
		if err != nil {
			logrus.Fatalf("Filter input read: %s", err)
		}
		defer f.Close()

		data, err := ioutil.ReadAll(f)
		if err != nil {
			logrus.Fatalf("Filter input read: %s", err)
		}
		var cfg filter.ConfigFileInput
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			logrus.Fatal(err)
		}

		filters := make(map[string]filter.Matcher)
		for name, conditions := range cfg {
			switch filter.NewFilterKind(viper.GetString("filter.kind")) {
			case filter.FilterKindSubnet:
				matcher, err := filter.NewConditionalSubnet(conditions)
				if err != nil {
					logrus.Fatal(err)
				}
				filters[name] = matcher
			case filter.FilterKindPort:
				matcher, err := filter.NewPortMatcher(conditions)
				if err != nil {
					logrus.Fatal(err)
				}
				filters[name] = matcher
			default:
				logrus.Fatalf(
					"invalid filter kind %s, expected %s",
					viper.GetString("filter.kind"),
					strings.Join(filter.FilterKinds, ", "),
				)
			}

		}

		tasks := make(chan filter.Task, workers)

		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(id int) {
				logrus.Infof("Worker %d started", id)
				defer wg.Done()
				defer logrus.Infof("Worker %d done", id)
				for task := range tasks {
					logrus.WithFields(logrus.Fields{
						"input":  task.Input,
						"output": task.Output,
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
						Filter:      task.Filter,
						Decapsulate: true,
						Compress:    true,
						StatFunc: func(fr filter.FilterResult) {
							logrus.Debugf("%+v", fr)
						},
					})
					if err != nil {
						logrus.Error(err)
					}
					logrus.Infof("%+v", result)
				}
			}(i)
		}

		files, err := fs.NewPcapList(input, "pcap")
		if err != nil {
			logrus.Fatalf("PCAP list gen: %s", err)
		}

		for _, fn := range files {
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

				tasks <- filter.Task{
					Input:       fn.Path,
					Output:      filepath.Join(outDir, filepath.Base(fn.Path)),
					Filter:      matcher,
					Description: name,
				}
			}
		}
		close(tasks)

		wg.Wait()
	},
}

func init() {
	rootCmd.AddCommand(filterCmd)

	filterCmd.PersistentFlags().String("filter-yaml", "filter.yml",
		`Source file for BPF filters. `+
			`Format is YAML. Key is name of the filter which also translates to output folder. `+
			`Value is a list of networks. Packets matching those networks will be written to output file.`)
	viper.BindPFlag("filter.yaml", filterCmd.PersistentFlags().Lookup("filter-yaml"))

	filterCmd.PersistentFlags().Int("filter-workers", 4, `Number of PCAP files to be parsed at once.`)
	viper.BindPFlag("filter.workers", filterCmd.PersistentFlags().Lookup("filter-workers"))

	filterCmd.PersistentFlags().String("filter-input", "", `Input folder for filtered PCAP files.`)
	viper.BindPFlag("filter.input", filterCmd.PersistentFlags().Lookup("filter-input"))

	filterCmd.PersistentFlags().String("filter-output", "", `Output folder for filtered PCAP files.`)
	viper.BindPFlag("filter.output", filterCmd.PersistentFlags().Lookup("filter-output"))

	filterCmd.PersistentFlags().String(
		"filter-kind",
		filter.FilterKinds[0],
		fmt.Sprintf("Select filtering modes. Supported are %s", strings.Join(filter.FilterKinds, ",")),
	)
	viper.BindPFlag("filter.kind", filterCmd.PersistentFlags().Lookup("filter-kind"))
}
