package mgr

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// routeNames collects every route a screen can reach: string literals passed to
// dispatch/runFlow/registered, plus the values of map literals of routes (the
// tunnel page's key-to-flow table).
func routeNames(t *testing.T) map[string]string {
	t.Helper()
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	names := map[string]string{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || (id.Name != "dispatch" && id.Name != "runFlow" && id.Name != "registered") || len(call.Args) == 0 {
				return true
			}
			if lit, ok := call.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				s, _ := strconv.Unquote(lit.Value)
				names[s] = fset.Position(lit.Pos()).String()
			}
			return true
		})
	}
	return names
}

// TestEveryRouteRegistered: a screen that dispatches a route nobody registered
// shows "not available" (or nothing) instead of working.
func TestEveryRouteRegistered(t *testing.T) {
	var missing []string
	for n, at := range routeNames(t) {
		if !registered(n) {
			missing = append(missing, n+"  ("+at+")")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("%d routes are dispatched but not registered:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
}
