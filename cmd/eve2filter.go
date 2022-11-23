/*
Copyright © 2022 Stamus Networks oss@stamus-networks.com

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
	"os"

	"github.com/StamusNetworks/gophercap/pkg/filter"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

// eve2filterCmd represents the eve2filter command
var eve2filterCmd = &cobra.Command{
	Use:   "eve2filter",
	Short: "Generate filter YAMLs from EVE events",
	Run: func(cmd *cobra.Command, args []string) {
		evePath := viper.GetString("eve2filter.path.eve")
		if evePath == "" {
			logrus.Fatal("EVE path missing")
		}
		filters, err := filter.Generate(evePath, func(err error) bool {
			logrus.Error(err)
			return true
		})
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.WithField("count", len(filters)).Info("Filters extracted")
		bin, err := yaml.Marshal(filters)
		if err != nil {
			logrus.Fatal(err)
		}
		logrus.WithField("path", viper.GetString("eve2filter.path.filter")).Info("Writing filters")
		f, err := os.Create(viper.GetString("eve2filter.path.filter"))
		if err != nil {
			logrus.Fatal(err)
		}
		defer f.Close()
		f.Write(bin)
	},
}

func init() {
	rootCmd.AddCommand(eve2filterCmd)

	eve2filterCmd.PersistentFlags().String("path-eve", "", "Path to EVE JSON.")
	viper.BindPFlag("eve2filter.path.eve", eve2filterCmd.PersistentFlags().Lookup("path-eve"))

	eve2filterCmd.PersistentFlags().String(
		"path-filter",
		"./filter-generated.yaml",
		"Path to resulting filter YAML",
	)
	viper.BindPFlag("eve2filter.path.filter", eve2filterCmd.PersistentFlags().Lookup("path-filter"))
}
