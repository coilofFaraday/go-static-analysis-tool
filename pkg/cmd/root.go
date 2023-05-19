package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "sast",
	Short: "A static analysis security testing tool for Go projects",
	Long: `A Static Analysis Security Testing (SAST) tool built with love by yourusername.
Complete documentation is available at http://yourwebsite.com`,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
