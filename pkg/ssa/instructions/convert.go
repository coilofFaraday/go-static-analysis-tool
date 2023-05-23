package instructions

import (
	"github.com/yourusername/yourprojectname/ssa"
	"github.com/yourusername/yourprojectname/utils"
)

// ConvertAnalyzer 是一个结构体，包含有关每个转换分析器的信息
type ConvertAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewConvertAnalyzer 返回一个新的 ConvertAnalyzer 结构体
func NewConvertAnalyzer(ta *utils.TaintAnalyzer) *ConvertAnalyzer {
	return &ConvertAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Convert 指令。如果该指令的 X 是污点，那么结果也是污点。
func (a *ConvertAnalyzer) Analyze(instr *ssa.Convert) {
	// 如果 Convert 指令的 X 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.X] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
