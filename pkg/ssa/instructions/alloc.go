package instructions

import (
	"fmt"
	"github.com/coiloffaraday/go-static-analysis-tool/utils"
	"golang.org/x/tools/go/ssa"
)

// AllocAnalyzer represents an analyzer for Alloc instructions.
type AllocAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
	Allocations   map[*ssa.Alloc]bool
}

// NewAllocAnalyzer creates a new AllocAnalyzer.
func NewAllocAnalyzer(taintAnalyzer *utils.TaintAnalyzer) *AllocAnalyzer {
	return &AllocAnalyzer{
		TaintAnalyzer: taintAnalyzer,
		Allocations:   make(map[*ssa.Alloc]bool),
	}
}

// Analyze performs the analysis for Alloc instructions.
func (a *AllocAnalyzer) Analyze(instr *ssa.Alloc) {
	// If the Alloc instruction's Comment is "tainted", mark the result as tainted.
	if instr.Comment == "tainted" {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}

	// Mark the allocation as not freed.
	a.Allocations[instr] = false
}

// MarkAsFreed marks an allocation as freed.
func (a *AllocAnalyzer) MarkAsFreed(instr *ssa.Alloc) {
	a.Allocations[instr] = true
}

// CheckForLeaks checks for memory leaks.
func (a *AllocAnalyzer) CheckForLeaks() {
	for alloc, freed := range a.Allocations {
		if !freed {
			// TODO: Report a memory leak.
			fmt.Printf("Potential memory leak: %v\n", alloc)
		}
	}
}
