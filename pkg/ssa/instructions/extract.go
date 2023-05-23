package instructions

import (
	"github.com/yourusername/yourprojectname/ssa"
	"github.com/yourusername/yourprojectname/utils"
)

// ExtractAnalyzer 是一个结构体，包含有关每个提取分析器的信息
type ExtractAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewExtractAnalyzer 返回一个新的 ExtractAnalyzer 结构体
func NewExtractAnalyzer(ta *utils.TaintAnalyzer) *ExtractAnalyzer {
	return &ExtractAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Extract 指令。如果该指令的 Tuple 是污点，那么结果也是污点。
func (a *ExtractAnalyzer) Analyze(instr *ssa.Extract) {
	// 如果 Extract 指令的 Tuple 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.Tuple] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
