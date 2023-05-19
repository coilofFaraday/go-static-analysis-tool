package cmd

import (
	"fmt"
	"github.com/coiloffaraday/go-static-analysis-tool/rules"
	"github.com/coiloffaraday/go-static-analysis-tool/ssa"
	"github.com/spf13/cobra"
	"os"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan a Go project for security vulnerabilities",
	Long:  `Scan a Go project for security vulnerabilities using the specified rule file.`,
	Run: func(cmd *cobra.Command, args []string) {
		projectPath, _ := cmd.Flags().GetString("project")
		ruleFile, _ := cmd.Flags().GetString("rule")

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
	},
}

func init() {
	scanCmd.Flags().StringP("project", "p", "", "Path to the Go project to analyze")
	scanCmd.Flags().StringP("rule", "r", "", "Path to the rule file")
}
