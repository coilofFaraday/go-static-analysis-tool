package instructions

import (
	"github.com/yourusername/yourprojectname/ssa"
	"github.com/yourusername/yourprojectname/utils"
)

// FieldAddrAnalyzer 是一个结构体，包含有关每个字段地址分析器的信息
type FieldAddrAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewFieldAddrAnalyzer 返回一个新的 FieldAddrAnalyzer 结构体
func NewFieldAddrAnalyzer(ta *utils.TaintAnalyzer) *FieldAddrAnalyzer {
	return &FieldAddrAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.FieldAddr 指令。如果该指令的 X 是污点，那么结果也是污点。
func (a *FieldAddrAnalyzer) Analyze(instr *ssa.FieldAddr) {
	// 如果 FieldAddr 指令的 X 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.X] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
