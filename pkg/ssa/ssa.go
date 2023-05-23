package ssa

import (
	"github.com/yourusername/yourprojectname/instructions"
	"github.com/yourusername/yourprojectname/utils"
	"golang.org/x/tools/go/ssa"
)

// SSAAnalyzer 是一个结构体，包含有关每个 SSA 分析器的信息
type SSAAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
	AllocAnalyzer *instructions.AllocAnalyzer
	BinOpAnalyzer *instructions.BinOpAnalyzer
	CallAnalyzer  *instructions.CallAnalyzer
	// 其他分析器...
}

// NewSSAAnalyzer 返回一个新的 SSAAnalyzer 结构体
func NewSSAAnalyzer(ta *utils.TaintAnalyzer) *SSAAnalyzer {
	return &SSAAnalyzer{
		TaintAnalyzer: ta,
		AllocAnalyzer: instructions.NewAllocAnalyzer(ta),
		BinOpAnalyzer: instructions.NewBinOpAnalyzer(ta),
		CallAnalyzer:  instructions.NewCallAnalyzer(ta),
		// 其他分析器...
	}
}

// Analyze 分析一个 ssa.Instruction。根据指令的类型，调用相应的分析器进行分析。
func (a *SSAAnalyzer) Analyze(instr ssa.Instruction) {
	switch instr := instr.(type) {
	case *ssa.Alloc:
		a.AllocAnalyzer.Analyze(instr)
	case *ssa.BinOp:
		a.BinOpAnalyzer.Analyze(instr)
	case *ssa.Call:
		a.CallAnalyzer.Analyze(instr)
	// 其他类型的指令...
	default:
		// 对于未知类型的指令，我们可以打印一条警告消息，但不做任何操作。
	}
}
