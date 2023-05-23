package instructions

import (
	"go-static-analysis-tool/pkg/ssa"
	"go-static-analysis-tool/pkg/utils"
)

// CallAnalyzer 是一个结构体，包含有关每个调用分析器的信息
type CallAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewCallAnalyzer 返回一个新的 CallAnalyzer 结构体
func NewCallAnalyzer(ta *utils.TaintAnalyzer) *CallAnalyzer {
	return &CallAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Call 指令。如果该指令的函数名是 "tainted"，则将结果标记为污点。
func (a *CallAnalyzer) Analyze(instr *ssa.Call) {
	// 如果 Call 指令的函数名是 "tainted"，则将结果标记为污点。
	if instr.Call.Value.Name() == "tainted" {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
