package instructions

import (
	"go-static-analysis-tool/pkg/ssa"
	"go-static-analysis-tool/pkg/utils"
)

// BuiltinAnalyzer 是一个结构体，包含有关每个内置函数分析器的信息
type BuiltinAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewBuiltinAnalyzer 返回一个新的 BuiltinAnalyzer 结构体
func NewBuiltinAnalyzer(ta *utils.TaintAnalyzer) *BuiltinAnalyzer {
	return &BuiltinAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Builtin 指令。如果该指令的 Name 是 "tainted"，则将结果标记为污点。
func (a *BuiltinAnalyzer) Analyze(instr *ssa.Builtin) {
	// 如果 Builtin 指令的 Name 是 "tainted"，则将结果标记为污点。
	if instr.Name() == "tainted" {
		for _, arg := range instr.Args {
			a.TaintAnalyzer.TaintedValues[arg] = true
		}
	}
}
