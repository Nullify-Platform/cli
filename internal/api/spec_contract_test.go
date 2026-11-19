package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// The generated client cannot call a route the spec does not list, but a
// hand-written call can. These tests read every hand-written Go file and
// check that each API path it names, with its method where the call names
// one, is in the spec the typed client is generated from. A hand-written call
// that keeps a path after the API moves it then fails here instead of
// returning 404 to users.

const specFile = "../../spec/nullify-openapi-bundle.yaml"

// privateRoutes are routes that hand-written code calls and that the API
// serves but leaves out of the published spec.
var privateRoutes = map[string]string{
	"/auth/cli/config":  "CLI sign-in: the login flow reads the API host to sign in against",
	"/auth/cli/session": "CLI sign-in: starts a browser login session",
	"/auth/cli/token":   "CLI sign-in: redeems the browser login for a token",
}

// specRoutes maps each spec path, with its parameters written as {}, to the
// methods the spec lists for it.
type specRoutes map[string]map[string]bool

func loadSpecRoutes(t *testing.T) specRoutes {
	t.Helper()
	data, err := os.ReadFile(specFile)
	require.NoError(t, err)

	var spec struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	require.NoError(t, yaml.Unmarshal(data, &spec))
	require.NotEmpty(t, spec.Paths, "the spec lists no paths")

	routes := specRoutes{}
	for path, operations := range spec.Paths {
		methods := map[string]bool{}
		for method := range operations {
			methods[strings.ToUpper(method)] = true
		}
		routes[specParam.ReplaceAllString(path, "{}")] = methods
	}
	return routes
}

var specParam = regexp.MustCompile(`\{[^}]*\}`)

// services are the first path segments the spec uses, such as "dast".
func (r specRoutes) services() map[string]bool {
	services := map[string]bool{}
	for path := range r {
		services[firstSegment(path)] = true
	}
	return services
}

// has reports whether the spec lists path, for method when it is set. A
// path that ends in "/" is a prefix that code completes at run time.
func (r specRoutes) has(method, path string) bool {
	for specPath, methods := range r {
		matched := specPath == path || (strings.HasSuffix(path, "/") && strings.HasPrefix(specPath, path))
		if matched && (method == "" || methods[method]) {
			return true
		}
	}
	return false
}

// handWrittenRoute is one API path a hand-written file names.
type handWrittenRoute struct {
	Pos    string
	Method string
	Path   string
}

var (
	formatVerb     = regexp.MustCompile(`%[a-zA-Z]`)
	hostPrefix     = regexp.MustCompile(`^(https?://)?%s`)
	methodLiteral  = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}
	httpMethodName = map[string]string{"MethodGet": "GET", "MethodPost": "POST", "MethodPut": "PUT", "MethodPatch": "PATCH", "MethodDelete": "DELETE"}
	doMethodFunc   = regexp.MustCompile(`^Do(Get|Post|Put|Patch|Delete)`)
)

// apiPath turns a string literal into the API path it names, or "" when it
// names none. A leading host ("%s" or "https://%s") and a query are dropped,
// and format verbs become {}.
func apiPath(literal string, services map[string]bool) string {
	path := hostPrefix.ReplaceAllString(literal, "")
	path, _, _ = strings.Cut(path, "?")
	if !strings.HasPrefix(path, "/") || !services[firstSegment(path)] {
		return ""
	}
	return formatVerb.ReplaceAllString(path, "{}")
}

func firstSegment(path string) string {
	segment, _, _ := strings.Cut(strings.TrimPrefix(path, "/"), "/")
	return segment
}

// routesInSource lists the API paths that one Go file names, with the method
// of the nearest enclosing call that names one.
func routesInSource(fset *token.FileSet, file *ast.File, services map[string]bool) []handWrittenRoute {
	var routes []handWrittenRoute
	var calls []*ast.CallExpr

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		switch node := n.(type) {
		case *ast.CallExpr:
			calls = append(calls, node)
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			literal, err := strconv.Unquote(node.Value)
			if err != nil {
				return true
			}
			if path := apiPath(literal, services); path != "" {
				routes = append(routes, handWrittenRoute{
					Pos:    fset.Position(node.Pos()).String(),
					Method: enclosingMethod(calls, node),
					Path:   path,
				})
			}
		}
		return true
	})
	return routes
}

// enclosingMethod returns the HTTP method of the innermost call around lit
// that names one, or "".
func enclosingMethod(calls []*ast.CallExpr, lit *ast.BasicLit) string {
	for i := len(calls) - 1; i >= 0; i-- {
		call := calls[i]
		if lit.Pos() < call.Pos() || lit.End() > call.End() {
			continue
		}
		if method := callMethod(call); method != "" {
			return method
		}
	}
	return ""
}

func callMethod(call *ast.CallExpr) string {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if m := doMethodFunc.FindStringSubmatch(sel.Sel.Name); m != nil {
			return strings.ToUpper(m[1])
		}
	}
	for _, arg := range call.Args {
		switch a := arg.(type) {
		case *ast.BasicLit:
			if value, err := strconv.Unquote(a.Value); err == nil && methodLiteral[value] {
				return value
			}
		case *ast.SelectorExpr:
			if method, ok := httpMethodName[a.Sel.Name]; ok {
				return method
			}
		}
	}
	return ""
}

// handWrittenRoutes reads every Go file under the CLI's cmd and internal
// directories that is neither generated nor a test.
func handWrittenRoutes(t *testing.T, services map[string]bool) []handWrittenRoute {
	t.Helper()
	fset := token.NewFileSet()
	var routes []handWrittenRoute

	for _, root := range []string{"../../cmd", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			if !ast.IsGenerated(file) {
				routes = append(routes, routesInSource(fset, file, services)...)
			}
			return nil
		})
		require.NoError(t, err)
	}
	return routes
}

func TestHandWrittenCallsUseRoutesInTheSpec(t *testing.T) {
	spec := loadSpecRoutes(t)
	routes := handWrittenRoutes(t, spec.services())
	require.NotEmpty(t, routes, "found no hand-written API paths, so the scan is broken")

	var missing []string
	for _, r := range routes {
		if _, private := privateRoutes[r.Path]; private {
			continue
		}
		if !spec.has(r.Method, r.Path) {
			missing = append(missing, strings.TrimSpace(r.Pos+": "+r.Method+" "+r.Path))
		}
	}
	sort.Strings(missing)
	require.Empty(t, missing, "hand-written calls name routes that the spec does not list; use the generated client or a route from the spec")
}

func TestPrivateRoutesAreStillCalledAndStillPrivate(t *testing.T) {
	spec := loadSpecRoutes(t)
	called := map[string]bool{}
	for _, r := range handWrittenRoutes(t, spec.services()) {
		called[r.Path] = true
	}

	for path := range privateRoutes {
		require.True(t, called[path], "%s is no longer called; drop it from privateRoutes", path)
		require.False(t, spec.has("", path), "%s is now in the spec; drop it from privateRoutes", path)
	}
}

// TestSpecContractCatchesAStalePath runs the check on the code that called
// routes the API had removed, and on its replacement.
func TestSpecContractCatchesAStalePath(t *testing.T) {
	const source = `package client

func (c *NullifyClient) start(ctx context.Context, githubID, scanID string) error {
	url := fmt.Sprintf("%s/dast/scans?githubOwnerId=%s", c.BaseURL, githubID)
	if err := c.doJSON(ctx, "POST", url, nil, nil); err != nil {
		return err
	}
	update := fmt.Sprintf("%s/dast/external/%s?githubOwnerId=%s", c.BaseURL, scanID, githubID)
	if err := c.doJSON(ctx, "PATCH", update, nil, nil); err != nil {
		return err
	}
	_, err := c.do(ctx, "POST", c.BaseURL+"/dast/pentest/start", nil)
	return err
}
`
	spec := loadSpecRoutes(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "stale.go", source, 0)
	require.NoError(t, err)

	routes := routesInSource(fset, file, spec.services())

	require.Equal(t, []handWrittenRoute{
		{Pos: "stale.go:4:21", Path: "/dast/scans"},
		{Pos: "stale.go:8:24", Path: "/dast/external/{}"},
		{Pos: "stale.go:12:40", Method: "POST", Path: "/dast/pentest/start"},
	}, routes)
	require.False(t, spec.has(routes[0].Method, routes[0].Path))
	require.False(t, spec.has(routes[1].Method, routes[1].Path))
	require.True(t, spec.has(routes[2].Method, routes[2].Path))
	require.False(t, spec.has("DELETE", "/dast/pentest/start"), "a method the spec does not list fails")
}

func TestAPIPath(t *testing.T) {
	services := map[string]bool{"dast": true, "auth": true}

	tests := []struct {
		literal string
		want    string
	}{
		{literal: "/dast/pentest/scans/%s", want: "/dast/pentest/scans/{}"},
		{literal: "%s/dast/scans?githubOwnerId=%s", want: "/dast/scans"},
		{literal: "https://%s/auth/github_token", want: "/auth/github_token"},
		{literal: "/callback", want: ""},
		{literal: "GET /dast/pentest/scans", want: ""},
		{literal: "dast", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.literal, func(t *testing.T) {
			require.Equal(t, tt.want, apiPath(tt.literal, services))
		})
	}
}
