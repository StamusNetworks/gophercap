package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// exampleConfigCmd represents the exampleConfig command
var exampleConfigCmd = &cobra.Command{
	Use:   "exampleConfig",
	Short: "Generate example configuration file",
	Long: `Example usage:
gopherCap --config example.yml exampleConfig`,
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Infof("Writing config to %s", cfgFile)
		viper.WriteConfigAs(cfgFile)
	},
}

func init() {
	rootCmd.AddCommand(exampleConfigCmd)
}
