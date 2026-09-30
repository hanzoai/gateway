package gateway

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// apiSegment is the `/api/` PATH segment on a bare path or on one of our own
// hosts. A word character before the segment (gitlab.com/api/v4, a Jaeger
// collector's :14268/api/traces) is a third-party URL and passes; our hosts are
// named outright because to the first alternative they read the same way.
var apiSegment = regexp.MustCompile(`(^|[^.\w])/api(/|$)|hanzo\.(ai|id|bot|app|team|network)\S*/api(/|$)`)

// TestNoAPIPrefix fails if any Go string literal in this repo names a
// first-party `/api/` path: routes this gateway serves or proxies, and the
// requests its tests drive through them, all live under /v1/. It reads string
// literals via go/ast, so a comment recording a retired upstream shape is prose
// and passes; only a literal can be a route.
func TestNoAPIPrefix(t *testing.T) {
	self := "apiprefix_test.go"
	fset := token.NewFileSet()
	var offenders []string
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "node_modules", "testdata", ".git":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || path == self {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if apiSegment.MatchString(v) {
				offenders = append(offenders, fset.Position(lit.Pos()).String()+": "+lit.Value)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(offenders) > 0 {
		t.Fatalf("first-party /api/ path literal(s); routes are /v1/:\n%s", strings.Join(offenders, "\n"))
	}
}

// TestTeamRoutesNoAPI fails if routes.yaml maps hanzo.team under /api/.
func TestTeamRoutesNoAPI(t *testing.T) {
	b, err := os.ReadFile("routes.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc {
		hosts, ok := v.(map[string]any)
		if !ok {
			continue
		}
		routes, _ := hosts["hanzo.team"].([]any)
		for _, r := range routes {
			if p, _ := r.(map[string]any)["prefix"].(string); strings.HasPrefix(p, "/api") {
				t.Fatalf("hanzo.team routes %s; routes are /v1/", p)
			}
		}
	}
}
