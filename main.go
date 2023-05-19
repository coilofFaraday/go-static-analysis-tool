package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"go-static-analysis-tool/pkg/analyzer/rules"
	"go-static-analysis-tool/pkg/ssa"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "sast",
	Short: "A static analysis security testing tool for Go projects",
	Long: `A Static Analysis Security Testing (SAST) tool built with love by yourusername.
Complete documentation is available at http://yourwebsite.com`,
	Run: func(cmd *cobra.Command, args []string) {
		// TODO: Add your logic here
	},
}

func main() {
	projectPath, _ := rootCmd.Flags().GetString("project")
	ruleFile, _ := rootCmd.Flags().GetString("rule")

	if projectPath == "" || ruleFile == "" {
		fmt.Println("Please provide both project path and rule file")
		os.Exit(1)
	}

	// Load the rule file
	rules, err := rules.Load(ruleFile)
	if err != nil {
		fmt.Printf("Failed to load rule file: %v\n", err)
		os.Exit(1)
	}

	// Create a new SSA builder
	builder := ssa.NewBuilder()

	// Build the SSA representation of the project
	project, err := builder.Build(projectPath)
	if err != nil {
		fmt.Printf("Failed to build SSA representation of the project: %v\n", err)
		os.Exit(1)
	}

	// Run the analysis
	for _, rule := range rules {
		rule.Run(project)
	}
}

func init() {
	rootCmd.Flags().StringP("project", "p", "", "Path to the Go project to analyze")
	rootCmd.Flags().StringP("rule", "r", "", "Path to the rule file")
}
