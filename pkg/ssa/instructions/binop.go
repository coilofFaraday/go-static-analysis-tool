package instructions

import (
	"github.com/yourusername/yourprojectname/ssa"
	"github.com/yourusername/yourprojectname/utils"
)

// BinOpAnalyzer 是一个结构体，包含有关每个二元操作分析器的信息
type BinOpAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewBinOpAnalyzer 返回一个新的 BinOpAnalyzer 结构体
func NewBinOpAnalyzer(ta *utils.TaintAnalyzer) *BinOpAnalyzer {
	return &BinOpAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.BinOp 指令。如果该指令的 X 或 Y 是污点，那么结果也是污点。
func (a *BinOpAnalyzer) Analyze(instr *ssa.BinOp) {
	// 如果 BinOp 指令的 X 或 Y 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.X] || a.TaintAnalyzer.TaintedValues[instr.Y] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
