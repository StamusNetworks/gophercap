package cmd

import (
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// exampleConfigCmd represents the exampleConfig command
var exampleConfigCmd = &cobra.Command{
	Use:   "exampleConfig",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		logrus.Infof("Writing config to %s", cfgFile)
		viper.WriteConfigAs(cfgFile)
	},
}

func init() {
	rootCmd.AddCommand(exampleConfigCmd)
}
