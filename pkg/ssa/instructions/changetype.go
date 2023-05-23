package instructions

import (
	"go-static-analysis-tool/pkg/ssa"
	"go-static-analysis-tool/pkg/utils"
)

// ChangeTypeAnalyzer 是一个结构体，包含有关每个类型变更分析器的信息
type ChangeTypeAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewChangeTypeAnalyzer 返回一个新的 ChangeTypeAnalyzer 结构体
func NewChangeTypeAnalyzer(ta *utils.TaintAnalyzer) *ChangeTypeAnalyzer {
	return &ChangeTypeAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.ChangeType 指令。如果该指令的 X 是污点，那么结果也是污点。
func (a *ChangeTypeAnalyzer) Analyze(instr *ssa.ChangeType) {
	// 如果 ChangeType 指令的 X 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.X] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
