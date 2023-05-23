package instructions

import (
	"go-static-analysis-tool/pkg/ssa"
	"go-static-analysis-tool/pkg/utils"
)

// ConstAnalyzer 是一个结构体，包含有关每个常量分析器的信息
type ConstAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewConstAnalyzer 返回一个新的 ConstAnalyzer 结构体
func NewConstAnalyzer(ta *utils.TaintAnalyzer) *ConstAnalyzer {
	return &ConstAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Const 指令。如果该指令的值是 "tainted"，则将结果标记为污点。
func (a *ConstAnalyzer) Analyze(instr *ssa.Const) {
	// 如果 Const 指令的值是 "tainted"，则将结果标记为污点。
	if instr.Value.String() == "tainted" {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
