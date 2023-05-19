package ssa

import (
	"go-static-analysis-tool/pkg/ssa/instructions"
	"go-static-analysis-tool/pkg/utils"
	"go/ast"
	"go/importer"
	"go/token"
	"go/types"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"log"
)

// AnalyzeProgram analyzes the given Go program.
func AnalyzeProgram(files map[string]*ast.File, fset *token.FileSet) {
	// Create a new type checker config.
	conf := types.Config{Importer: importer.Default()}

	// Type check the program.
	info := &types.Info{
		Defs: make(map[*ast.Ident]types.Object),
		Uses: make(map[*ast.Ident]types.Object),
	}
	_, err := conf.Check("cmd", fset, files, info)
	if err != nil {
		log.Fatal(err)
	}

	// Create the SSA program.
	prog := ssautil.CreateProgram(info, ssa.BuilderMode(0))

	// Build SSA.
	prog.Build()

	// Create a new taint analyzer.
	taintAnalyzer := utils.NewTaintAnalyzer()

	// Create analyzers for each instruction type.
	allocAnalyzer := instructions.NewAllocAnalyzer(taintAnalyzer)
	binopAnalyzer := instructions.NewBinOpAnalyzer(taintAnalyzer)
	// TODO: Create more analyzers as needed.

	// Analyze each function.
	for _, pkg := range prog.AllPackages() {
		for _, fn := range pkg.Members {
			if fn, ok := fn.(*ssa.Function); ok {
				for _, block := range fn.Blocks {
					for _, instr := range block.Instrs {
						switch instr := instr.(type) {
						case *ssa.Alloc:
							allocAnalyzer.Analyze(instr)
						case *ssa.BinOp:
							binopAnalyzer.Analyze(instr)
							// TODO: Analyze more instruction types as needed.
						}
					}
				}
			}
		}
	}
}
