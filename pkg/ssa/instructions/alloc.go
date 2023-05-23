package instructions

import (
	"go-static-analysis-tool/pkg/ssa"
	"go-static-analysis-tool/pkg/utils"
)

// AllocAnalyzer 是一个结构体，包含有关每个分配分析器的信息
type AllocAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
	Allocations   map[*ssa.Alloc]bool
}

// NewAllocAnalyzer 返回一个新的 AllocAnalyzer 结构体
func NewAllocAnalyzer(ta *utils.TaintAnalyzer) *AllocAnalyzer {
	return &AllocAnalyzer{
		TaintAnalyzer: ta,
		Allocations:   make(map[*ssa.Alloc]bool),
	}
}

// Analyze 分析一个 ssa.Alloc 指令。如果该指令的 Comment 是 "tainted"，则将结果标记为污点。然后，将分配标记为未释放。
func (a *AllocAnalyzer) Analyze(instr *ssa.Alloc) {
	// If the Alloc instruction's Comment is "tainted", mark the result as tainted.
	if instr.Comment() == "tainted" {
		a.TaintAnalyzer.TaintedValues[ssa.Value(instr)] = true
	}

	// Mark the allocation as not freed.
	a.Allocations[instr] = false
}
