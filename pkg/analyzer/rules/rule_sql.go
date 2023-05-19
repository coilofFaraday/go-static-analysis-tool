package rules

import (
	"github.com/coiloffaraday/go-static-analysis-tool/ssa"
	"github.com/coiloffaraday/go-static-analysis-tool/utils"
)

// SQLInjectionRule defines a rule for detecting SQL Injection vulnerabilities.
type SQLInjectionRule struct{}

// NewSQLInjectionRule creates a new SQLInjectionRule.
func NewSQLInjectionRule() *SQLInjectionRule {
	return &SQLInjectionRule{}
}

// Name returns the name of this rule.
func (r *SQLInjectionRule) Name() string {
	return "sql_injection"
}

// Run applies the rule to the given function.
func (r *SQLInjectionRule) Run(fn *ssa.Function, report utils.Reporter) {
	// Define a set of functions that are known to be vulnerable to SQL injection.
	vulnerableFuncs := map[string][]string{
		"(*database/sql.DB)": {"Exec", "ExecContext", "Query", "QueryContext", "QueryRow", "QueryRowContext"},
	}

	// Iterate over the instructions in the function.
	for _, instr := range fn.Instructions {
		call, ok := instr.(*ssa.Call)
		if !ok {
			continue
		}

		// Check if the function being called is in the list of vulnerable functions.
		for pkg, funcs := range vulnerableFuncs {
			for _, fn := range funcs {
				if call.Call.StaticCallee().Pkg.Path() == pkg && call.Call.StaticCallee().Name() == fn {
					// We found a call to a potentially vulnerable function.
					// Now we need to check if any of the arguments to the function are tainted.
					taintAnalyzer := utils.NewTaintAnalyzer()
					argIndex := 1
					if call.Call.StaticCallee().Name() == "Context" {
						argIndex = 2
					}
					if taintAnalyzer.ContainsTaint(call, call.Call.Args[argIndex]) {
						// We found a potential SQL injection vulnerability.
						report.Add("可能存在SQL注入漏洞", fn, instr.Pos())
					}
				}
			}
		}
	}
}
