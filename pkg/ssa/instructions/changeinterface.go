package instructions

import (
	"go-static-analysis-tool/pkg/ssa"
	"go-static-analysis-tool/pkg/utils"
)

// ChangeInterfaceAnalyzer 是一个结构体，包含有关每个接口变更分析器的信息
type ChangeInterfaceAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewChangeInterfaceAnalyzer 返回一个新的 ChangeInterfaceAnalyzer 结构体
func NewChangeInterfaceAnalyzer(ta *utils.TaintAnalyzer) *ChangeInterfaceAnalyzer {
	return &ChangeInterfaceAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.ChangeInterface 指令。如果该指令的 X 是污点，那么结果也是污点。
func (a *ChangeInterfaceAnalyzer) Analyze(instr *ssa.ChangeInterface) {
	// 如果 ChangeInterface 指令的 X 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.X] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
