package rules

import (
	"github.com/your_project/ssa"
	"github.com/your_project/taint"
	"github.com/your_project/utils"
)

// RuleSQL is a rule for detecting SQL injection.
type RuleSQL struct {
	// The taint analyzer for this rule.
	TaintAnalyzer *taint.TaintAnalyzer
}

// NewRuleSQL creates a new RuleSQL.
func NewRuleSQL() *RuleSQL {
	return &RuleSQL{
		TaintAnalyzer: taint.NewTaintAnalyzer(),
	}
}

// GetName returns the name of this rule.
func (r *RuleSQL) GetName() string {
	return "SQL Injection"
}

// GetID returns the ID of this rule.
func (r *RuleSQL) GetID() string {
	return "RULE_SQL"
}

// Check checks if the given SSA function contains a potential SQL injection.
func (r *RuleSQL) Check(fn *ssa.Function) []*utils.Finding {
	var findings []*utils.Finding

	// Iterate over the instructions in the function.
	for _, block := range fn.Blocks {
		for _, instr := range block.Instrs {
			// Check if the instruction is a call instruction.
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}

			// Check if the call is to a function that can execute SQL queries.
			if utils.IsSQLQueryFunction(call.Call.Value) {
				// Check if the argument to the function is tainted.
				if r.TaintAnalyzer.IsTainted(call.Call.Args[0]) {
					// If the argument is tainted, add a finding.
					findings = append(findings, utils.NewFinding(fn, instr, r))
				}
			}
		}
	}

	return findings
}
