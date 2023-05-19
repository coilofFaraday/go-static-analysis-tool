package taint

import (
	"go/token"
	"go/types"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/ssa"
	"hash/fnv"
)

// TaintedCode is a struct that contains information about the vulnerable line of code
type TaintedCode struct {
	SourceCode     string
	SourceFilename string
	SourceLineNum  int
	ParentFunction string
}

// MapData is a struct that contains information about each hash
type MapData struct {
	Mapped     bool // whether a hash has already been mapped
	Vulnerable bool // whether a hash has been found vulnerable
	Count      int  // the number of times a hash has been visited
}

// TaintAnalyzer is a struct that contains information about each taint analyzer
type TaintAnalyzer struct {
	taint_map   map[uint64]MapData
	TaintSource []TaintedCode
	pass        *analysis.Pass
	location    token.Pos
}

// CreateTaintAnalyzer returns a new TaintAnalyzer struct
func CreateTaintAnalyzer(pass *analysis.Pass, location token.Pos) TaintAnalyzer {
	return TaintAnalyzer{
		make(map[uint64]MapData),
		[]TaintedCode{},
		pass,
		location,
	}
}

// ContainsTaint analyzes the ssa.Value, recursively traces the value to all possible sources, and returns True if any of the sources are vulnerable. It returns False otherwise.
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
