package instructions

import (
	"go-static-analysis-tool/pkg/utils"
	"golang.org/x/tools/go/ssa"
)

// BinOpAnalyzer represents an analyzer for BinOp instructions.
type BinOpAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewBinOpAnalyzer creates a new BinOpAnalyzer.
func NewBinOpAnalyzer(taintAnalyzer *utils.TaintAnalyzer) *BinOpAnalyzer {
	return &BinOpAnalyzer{
		TaintAnalyzer: taintAnalyzer,
	}
}

// Analyze performs the analysis for BinOp instructions.
func (a *BinOpAnalyzer) Analyze(instr *ssa.BinOp) {
	// If either operand is tainted, mark the result as tainted.
	if a.TaintAnalyzer.TaintedValues[instr.X] || a.TaintAnalyzer.TaintedValues[instr.Y] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}

	// TODO: Check for potential integer overflows, divisions by zero, etc.
}
