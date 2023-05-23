package utils

import (
	"go/token"
	"go/types"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
	"hash/fnv"
)

// TaintedCode 是一个结构体，包含有关易受攻击的代码行的信息
type TaintedCode struct {
	SourceCode     string
	SourceFilename string
	SourceLineNum  int
	ParentFunction string
}

// MapData 是一个结构体，包含有关每个哈希的信息
type MapData struct {
	Mapped     bool // 是否已经映射了一个哈希
	Vulnerable bool // 是否发现一个哈希是易受攻击的
	Count      int  // 一个哈希被访问的次数
}

// TaintAnalyzer 是一个结构体，包含有关每个污点分析器的信息
type TaintAnalyzer struct {
	taint_map     map[uint64]MapData
	TaintSource   []TaintedCode
	pass          *analysis.Pass
	location      token.Pos
	TaintedValues map[ssa.Value]bool
}

// CreateTaintAnalyzer 返回一个新的 TaintAnalyzer 结构体
func CreateTaintAnalyzer(pass *analysis.Pass, location token.Pos) TaintAnalyzer {
	return TaintAnalyzer{
		taint_map:     make(map[uint64]MapData),
		TaintSource:   []TaintedCode{},
		pass:          pass,
		location:      location,
		TaintedValues: make(map[ssa.Value]bool),
	}
}

// ContainsTaint 分析 ssa.Value，递归追踪值到所有可能的源，如果任何源是易受攻击的，则返回 True。否则返回 False。
func (ta *TaintAnalyzer) ContainsTaint(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph) bool {
	return ta.ContainsTaintRecurse(startCall, val, cg, 0, []ssa.Value{})
}

// ContainsTaintRecurse is the main function for taint analysis
func (ta *TaintAnalyzer) ContainsTaintRecurse(startCall *ssa.CallCommon, val *ssa.Value, cg CallGraph, depth int, visitedMutable []ssa.Value) bool {
	// Check if the value is nil or if the depth exceeds the maximum depth
	if val == nil || depth > MaxDepth {
		return false
	}

	// Check if the value is in the visited list
	for _, visited := range visitedMutable {
		if visited == *val {
			return false
		}
	}

	// Add the value to the visited list
	visitedMutable = append(visitedMutable, *val)

	// Check if the value is a source of taint
	if ta.isSource(*val) {
		return true
	}

	// Check if the value is an instruction
	instr, ok := (*val).(*ssa.Instruction)
	if ok {
		// Check if the instruction is a call
		call, ok := (*instr).(*ssa.Call)
		if ok {
			// Check if the call is a source of taint
			if ta.isSource(call) {
				return true
			}

			// Recursively check the arguments of the call
			for _, arg := range call.Call.Args {
				if ta.ContainsTaintRecurse(startCall, &arg, cg, depth+1, visitedMutable) {
					return true
				}
			}
		}

		// Check if the instruction is a store
		store, ok := (*instr).(*ssa.Store)
		if ok {
			// Recursively check the value being stored
			if ta.ContainsTaintRecurse(startCall, &store.Val, cg, depth+1, visitedMutable) {
				return true
			}
		}
	}

	// Recursively check the operands of the value
	for _, operand := range (*val).Operands(nil) {
		if ta.ContainsTaintRecurse(startCall, operand, cg, depth+1, visitedMutable) {
			return true
		}
	}

	return false
}

// isSource checks if a ssa.Value is a source of taint.
func (ta *TaintAnalyzer) isSource(val ssa.Value) bool {
	// Check if the value is a call
	call, ok := val.(*ssa.Call)
	if ok {
		// Check if the call is to a function that returns user input
		if ta.isSourceFunction(call.Call.StaticCallee()) {
			return true
		}
	}

	// Check if the value is a field access
	field, ok := val.(*ssa.FieldAddr)
	if ok {
		// Check if the field is a source of user input
		if ta.isSourceField(field) {
			return true
		}
	}

	// TODO: Add checks for other types of taint sources

	return false
}

// isSourceFunction checks if a function is a source of taint.
// isSourceFunction checks if a function is a source of taint.
func (ta *TaintAnalyzer) isSourceFunction(fn *ssa.Function) bool {
	// Check if the function is nil
	if fn == nil {
		return false
	}

	// Check if the function is a method of the http.Request struct
	if recv := fn.Signature.Recv(); recv != nil {
		if named, ok := recv.Type().(*types.Named); ok {
			if named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Request" {
				// Check if the function is one of the methods that can return user input
				switch fn.Name() {
				case "FormValue", "PostFormValue", "Cookie", "URL":
					return true
				}
			}
		}
	}

	return false
}

// isSourceField checks if a field is a source of taint.
func (ta *TaintAnalyzer) isSourceField(field *ssa.FieldAddr) bool {
	// Check if the field is a field of the http.Request struct
	if named, ok := field.X.Type().(*types.Named); ok {
		if named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Request" {
			// Check if the field is one of the fields that can contain user input
			switch field.Field.Name() {
			case "Form", "PostForm", "MultipartForm", "URL":
				return true
			}
		}
	}

	return false
}

// Memoize is used to store the result of taint analysis for a specific ssa.Value
// Memoize is used to store the result of taint analysis for a specific ssa.Value
func (ta *TaintAnalyzer) Memoize(val *ssa.Value, vulnerable bool) {
	// Calculate the hash of the ssa.Value
	hash := hashValue(*val)

	// Check if the hash is already in the taint map
	if data, ok := ta.taint_map[hash]; ok {
		// If the hash is already in the taint map, update the data
		data.Vulnerable = data.Vulnerable || vulnerable
		data.Count++
		ta.taint_map[hash] = data
	} else {
		// If the hash is not in the taint map, add it to the taint map
		ta.taint_map[hash] = MapData{
			Mapped:     true,
			Vulnerable: vulnerable,
			Count:      1,
		}
	}
}

func hashValue(val ssa.Value) uint64 {
	// Create a new FNV-1a hash.Hash64
	h := fnv.New64a()

	// Convert the ssa.Value to a string
	str := val.String()

	// Write the string to the hash.Hash64
	h.Write([]byte(str))

	// Calculate the hash
	hash := h.Sum64()

	return hash
}
