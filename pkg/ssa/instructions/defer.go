package instructions

import (
	"github.com/yourusername/yourprojectname/ssa"
	"github.com/yourusername/yourprojectname/utils"
)

// DeferAnalyzer 是一个结构体，包含有关每个延迟分析器的信息
type DeferAnalyzer struct {
	TaintAnalyzer *utils.TaintAnalyzer
}

// NewDeferAnalyzer 返回一个新的 DeferAnalyzer 结构体
func NewDeferAnalyzer(ta *utils.TaintAnalyzer) *DeferAnalyzer {
	return &DeferAnalyzer{
		TaintAnalyzer: ta,
	}
}

// Analyze 分析一个 ssa.Defer 指令。如果该指令的 Call 是污点，那么结果也是污点。
func (a *DeferAnalyzer) Analyze(instr *ssa.Defer) {
	// 如果 Defer 指令的 Call 是污点，那么结果也是污点。
	if a.TaintAnalyzer.TaintedValues[instr.Call.Value] {
		a.TaintAnalyzer.TaintedValues[instr] = true
	}
}
