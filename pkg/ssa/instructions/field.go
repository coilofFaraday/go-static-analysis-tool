package instructions

import (
	"github.com/yourusername/yourprojectname/ssa"
	"github.com/yourusername/yourprojectname/utils"
)

// FieldAnalyzer 是一个结构体，包含有关每个字段分析器的信息
type FieldAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewFieldAnalyzer 返回一个新的 FieldAnalyzer 结构体
func NewFieldAnalyzer(ta *utils.TaintAnalyzer) *FieldAnalyzer {
	return &FieldAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Field 指令。如果该指令的 X 是污点，那么结果也是污点。
func (a *FieldAnalyzer) Analyze(instr *ssa.Field)
	// 如果 Field 指令的 X 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.X] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
