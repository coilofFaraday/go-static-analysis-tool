package utils

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
)

// ParseFiles parses the Go source files located at the given paths and returns the corresponding ASTs.
func ParseFiles(paths []string) (map[string]*ast.File, *token.FileSet, error) {
	fset := token.NewFileSet()
	files := make(map[string]*ast.File)

	for _, path := range paths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, nil, err
		}

		file, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
		if err != nil {
			return nil, nil, err
		}

		files[path] = file
	}

	return files, fset, nil
}
