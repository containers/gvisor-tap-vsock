// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package modernize

// This file defines modernizers that use the "reflect" package.

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/edge"
	"golang.org/x/tools/go/types/typeutil"
	"golang.org/x/tools/internal/analysisinternal"
	"golang.org/x/tools/internal/analysisinternal/generated"
	typeindexanalyzer "golang.org/x/tools/internal/analysisinternal/typeindex"
	"golang.org/x/tools/internal/astutil"
	"golang.org/x/tools/internal/typesinternal"
	"golang.org/x/tools/internal/typesinternal/typeindex"
	"golang.org/x/tools/internal/versions"
)

var ReflectTypeForAnalyzer = &analysis.Analyzer{
	Name: "reflecttypefor",
	Doc:  analysisinternal.MustExtractDoc(doc, "reflecttypefor"),
	Requires: []*analysis.Analyzer{
		generated.Analyzer,
		inspect.Analyzer,
		typeindexanalyzer.Analyzer,
	},
	Run: reflecttypefor,
	URL: "https://pkg.go.dev/golang.org/x/tools/go/analysis/passes/modernize#reflecttypefor",
}

func reflecttypefor(pass *analysis.Pass) (any, error) {
	skipGenerated(pass)

	var (
		index = pass.ResultOf[typeindexanalyzer.Analyzer].(*typeindex.Index)
		info  = pass.TypesInfo

		reflectTypeOf = index.Object("reflect", "TypeOf")
	)

	for curCall := range index.Calls(reflectTypeOf) {
		call := curCall.Node().(*ast.CallExpr)
		// Have: reflect.TypeOf(expr)

		expr := call.Args[0]
		if !typesinternal.NoEffects(info, expr) {
			continue // don't eliminate operand: may have effects
		}

		t := info.TypeOf(expr)
		var edits []analysis.TextEdit

		// Special case for TypeOf((*T)(nil)).Elem(),
		// needed when T is an interface type.
		if astutil.IsChildOf(curCall, edge.SelectorExpr_X) {
			curSel := unparenEnclosing(curCall).Parent()
			if astutil.IsChildOf(curSel, edge.CallExpr_Fun) {
				call2 := unparenEnclosing(curSel).Parent().Node().(*ast.CallExpr)
				obj := typeutil.Callee(info, call2)
				if typesinternal.IsMethodNamed(obj, "reflect", "Type", "Elem") {
					if ptr, ok := t.(*types.Pointer); ok {
						// Have: reflect.TypeOf(...*T value...).Elem()
						// => reflect.TypeFor[T]()
						t = ptr.Elem()
						edits = []analysis.TextEdit{
							{
								// delete .Elem()
								Pos: call.End(),
								End: call2.End(),
							},
						}
					}
				}
			}
		}

		// TypeOf(x) where x has an interface type is a
		// dynamic operation; don't transform it to TypeFor.
		// (edits == nil means "not the Elem() special case".)
		if types.IsInterface(t) && edits == nil {
			continue
		}

		file := astutil.EnclosingFile(curCall)
		if versions.Before(info.FileVersions[file], "go1.22") {
			continue // TypeFor requires go1.22
		}

		// Format the type as valid Go syntax.
		// TODO(adonovan): FileQualifier needs to respect
		// visibility at the current point, and either fail
		// or edit the imports as needed.
		qual := typesinternal.FileQualifier(file, pass.Pkg)
		tstr := types.TypeString(t, qual)

		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue // e.g. reflect was dot-imported
		}

		pass.Report(analysis.Diagnostic{
			Pos:     call.Fun.Pos(),
			End:     call.Fun.End(),
			Message: "reflect.TypeOf call can be simplified using TypeFor",
			SuggestedFixes: []analysis.SuggestedFix{{
				// reflect.TypeOf    (...T value...)
				//         ------     -------------
				// reflect.TypeFor[T](             )
				Message: "Replace TypeOf by TypeFor",
				TextEdits: append([]analysis.TextEdit{
					{
						Pos:     sel.Sel.Pos(),
						End:     sel.Sel.End(),
						NewText: []byte("TypeFor[" + tstr + "]"),
					},
					// delete (pure) argument
					{
						Pos: call.Lparen + 1,
						End: call.Rparen,
					},
				}, edits...),
			}},
		})
	}

	return nil, nil
}
