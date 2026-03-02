// generate reads the merged OpenAPI spec and produces a typed Go API client
// and cobra command files for the CLI.
//
// Usage: go run ./scripts/generate/main.go --spec ../public-docs/specs/merged-openapi.yml
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

type OpenAPISpec struct {
	Paths      map[string]map[string]Operation `yaml:"paths"`
	Components struct {
		Schemas map[string]Schema `yaml:"schemas"`
	} `yaml:"components"`
}

type Operation struct {
	Summary     string      `yaml:"summary"`
	Description string      `yaml:"description"`
	Parameters  []Parameter `yaml:"parameters"`
	RequestBody *struct {
		Content map[string]struct {
			Schema SchemaRef `yaml:"schema"`
		} `yaml:"content"`
	} `yaml:"requestBody"`
	Responses map[string]struct {
		Description string `yaml:"description"`
		Content     map[string]struct {
			Schema SchemaRef `yaml:"schema"`
		} `yaml:"content"`
	} `yaml:"responses"`
}

type Parameter struct {
	Name        string    `yaml:"name"`
	In          string    `yaml:"in"`
	Description string    `yaml:"description"`
	Required    bool      `yaml:"required"`
	Schema      SchemaRef `yaml:"schema"`
}

type SchemaRef struct {
	Ref    string `yaml:"$ref"`
	Type   string `yaml:"type"`
	Format string `yaml:"format"`
	Items  *struct {
		Type   string `yaml:"type"`
		Format string `yaml:"format"`
	} `yaml:"items"`
}

type Schema struct {
	Type       string               `yaml:"type"`
	Properties map[string]SchemaRef `yaml:"properties"`
	Required   []string             `yaml:"required"`
}

// Service grouping based on path prefix
var serviceMapping = map[string]string{
	"/sast/":           "sast",
	"/sca/":            "sca",
	"/secrets/":        "secrets",
	"/dast/":           "dast",
	"/admin/":          "admin",
	"/manager/":        "manager",
	"/classifier/":     "classifier",
	"/cspm/":           "cspm",
	"/graph/":          "infrastructure",
	"/chat/":           "chat",
	"/orchestrator/":   "orchestrator",
	"/ticket/":         "ticket",
}

// serviceDescriptions maps service names to human-readable descriptions.
var serviceDescriptions = map[string]string{
	"sast":           "Static Application Security Testing (SAST)",
	"sca":            "Software Composition Analysis (SCA)",
	"secrets":        "Secrets Detection",
	"dast":           "Dynamic Application Security Testing (DAST)",
	"admin":          "Administration and Metrics",
	"manager":        "Finding Lifecycle Management",
	"classifier":     "Repository and Code Classification",
	"cspm":           "Cloud Security Posture Management (CSPM)",
	"infrastructure": "Infrastructure Graph",
	"chat":           "AI Chat",
	"orchestrator":   "Orchestration and Automation",
	"ticket":         "Ticket Integration",
}

// Paths to exclude from CLI generation
var excludePrefixes = []string{
	"/internal/",
	"/core/bitbucket/",
	"/core/jira/",
}

type Endpoint struct {
	Path        string
	Method      string
	Summary     string
	Description string
	Service     string
	Parameters  []Parameter
	HasBody     bool
	BodySchema  string
	OutputSchema string
	FuncName    string
	CobraCmd    string
	CobraPath   string
}

func main() {
	specPath := "../public-docs/specs/merged-openapi.yml"
	outputDir := "internal/api"
	cmdOutputDir := "internal/commands"

	for i, arg := range os.Args {
		if arg == "--spec" && i+1 < len(os.Args) {
			specPath = os.Args[i+1]
		}
		if arg == "--output" && i+1 < len(os.Args) {
			outputDir = os.Args[i+1]
		}
		if arg == "--cmd-output" && i+1 < len(os.Args) {
			cmdOutputDir = os.Args[i+1]
		}
	}

	data, err := os.ReadFile(specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading spec: %v\n", err)
		os.Exit(1)
	}

	var spec OpenAPISpec
	err = yaml.Unmarshal(data, &spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing spec: %v\n", err)
		os.Exit(1)
	}

	endpoints := extractEndpoints(spec)
	grouped := groupByService(endpoints)

	os.MkdirAll(outputDir, 0755)
	os.MkdirAll(cmdOutputDir, 0755)

	generateClient(outputDir, grouped)
	generateCommands(cmdOutputDir, grouped)

	fmt.Printf("Generated %d endpoints across %d services\n", len(endpoints), len(grouped))
	for svc, eps := range grouped {
		fmt.Printf("  %s: %d endpoints\n", svc, len(eps))
	}
}

func extractEndpoints(spec OpenAPISpec) []Endpoint {
	var endpoints []Endpoint

	for path, methods := range spec.Paths {
		// Skip excluded paths
		skip := false
		for _, prefix := range excludePrefixes {
			if strings.HasPrefix(path, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		for method, op := range methods {
			service := classifyService(path)
			if service == "" {
				continue
			}

			ep := Endpoint{
				Path:        path,
				Method:      strings.ToUpper(method),
				Summary:     op.Summary,
				Description: op.Description,
				Service:     service,
				Parameters:  op.Parameters,
				HasBody:     op.RequestBody != nil,
				FuncName:    generateFuncName(method, path),
				CobraCmd:    generateCobraCommand(path),
				CobraPath:   generateCobraPath(path),
			}

			// Extract output schema
			if resp, ok := op.Responses["200"]; ok {
				if content, ok := resp.Content["application/json"]; ok {
					ep.OutputSchema = extractSchemaName(content.Schema.Ref)
				}
			}

			// Extract body schema
			if op.RequestBody != nil {
				if content, ok := op.RequestBody.Content["application/json"]; ok {
					ep.BodySchema = extractSchemaName(content.Schema.Ref)
				}
			}

			endpoints = append(endpoints, ep)
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Service != endpoints[j].Service {
			return endpoints[i].Service < endpoints[j].Service
		}
		return endpoints[i].Path < endpoints[j].Path
	})

	return endpoints
}

func classifyService(path string) string {
	for prefix, service := range serviceMapping {
		if strings.HasPrefix(path, prefix) {
			return service
		}
	}
	return ""
}

func groupByService(endpoints []Endpoint) map[string][]Endpoint {
	grouped := make(map[string][]Endpoint)
	for _, ep := range endpoints {
		grouped[ep.Service] = append(grouped[ep.Service], ep)
	}
	return grouped
}

func generateFuncName(method, path string) string {
	// Convert path like /sast/findings/{id} to SastFindingsGetByID
	clean := strings.ReplaceAll(path, "{", "")
	clean = strings.ReplaceAll(clean, "}", "")
	parts := strings.Split(clean, "/")

	var name string
	switch strings.ToUpper(method) {
	case "GET":
		// Check if last segment looks like a path parameter
		if len(parts) > 0 && isIDSegment(parts[len(parts)-1]) {
			name = "Get"
		} else {
			name = "List"
		}
	case "POST":
		name = "Create"
	case "PUT":
		name = "Update"
	case "PATCH":
		name = "Patch"
	case "DELETE":
		name = "Delete"
	}

	for _, part := range parts {
		if part == "" {
			continue
		}
		name += toPascalCase(part)
	}

	return name
}

func generateCobraCommand(path string) string {
	// /sast/findings/{findingId} -> "sast findings get"
	// /sast/findings -> "sast findings list"
	parts := strings.Split(path, "/")
	var cmdParts []string
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "{") {
			continue
		}
		cmdParts = append(cmdParts, part)
	}
	return strings.Join(cmdParts, " ")
}

func generateCobraPath(path string) string {
	parts := strings.Split(path, "/")
	var cmdParts []string
	for _, part := range parts {
		if part == "" || strings.HasPrefix(part, "{") {
			continue
		}
		cmdParts = append(cmdParts, part)
	}
	return strings.Join(cmdParts, "/")
}

func isIDSegment(s string) bool {
	return strings.HasSuffix(s, "Id") || strings.HasSuffix(s, "ID") || s == "id"
}

var nonAlphaRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func toPascalCase(s string) string {
	s = nonAlphaRegex.ReplaceAllString(s, " ")
	words := strings.Fields(s)
	var result string
	for _, word := range words {
		if len(word) == 0 {
			continue
		}
		runes := []rune(word)
		runes[0] = unicode.ToUpper(runes[0])
		result += string(runes)
	}
	return result
}

func toKebabCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) && i > 0 {
			result.WriteRune('-')
		}
		result.WriteRune(unicode.ToLower(r))
	}
	// Also replace underscores with hyphens
	return strings.ReplaceAll(result.String(), "_", "-")
}

func extractSchemaName(ref string) string {
	if ref == "" {
		return ""
	}
	parts := strings.Split(ref, "/")
	return parts[len(parts)-1]
}

func generateClientFile(outputDir string, service string, endpoints []Endpoint) {
	filePath := filepath.Join(outputDir, service+".go")

	// Determine which imports are needed
	needsStrings := false
	needsIO := false
	for _, ep := range endpoints {
		for _, p := range ep.Parameters {
			if p.In == "path" {
				needsStrings = true
			}
		}
		if ep.HasBody {
			needsIO = true
		}
	}

	var sb strings.Builder
	sb.WriteString("// Code generated by scripts/generate/main.go. DO NOT EDIT.\npackage api\n\nimport (\n\t\"context\"\n\t\"fmt\"\n")
	if needsIO {
		sb.WriteString("\t\"io\"\n")
	}
	sb.WriteString("\t\"net/url\"\n")
	if needsStrings {
		sb.WriteString("\t\"strings\"\n")
	}
	sb.WriteString(")\n")

	for _, ep := range endpoints {
		sb.WriteString(fmt.Sprintf("\n// %s - %s\n// %s %s\n", ep.FuncName, ep.Summary, ep.Method, ep.Path))

		if ep.HasBody {
			sb.WriteString(fmt.Sprintf("func (c *Client) %s(ctx context.Context, params url.Values, body io.Reader) ([]byte, error) {\n", ep.FuncName))
		} else {
			sb.WriteString(fmt.Sprintf("func (c *Client) %s(ctx context.Context, params url.Values) ([]byte, error) {\n", ep.FuncName))
		}

		sb.WriteString(fmt.Sprintf("\tpath := %q\n", ep.Path))

		// Path parameter substitution
		for _, p := range ep.Parameters {
			if p.In == "path" {
				sb.WriteString(fmt.Sprintf("\tpath = strings.Replace(path, \"{%s}\", params.Get(%q), 1)\n", p.Name, p.Name))
			}
		}

		sb.WriteString("\n\tquery := url.Values{}\n\tfor k, v := range c.DefaultParams {\n\t\tquery.Set(k, v)\n\t}\n")

		for _, p := range ep.Parameters {
			if p.In == "query" {
				sb.WriteString(fmt.Sprintf("\tif v := params.Get(%q); v != \"\" {\n\t\tquery.Set(%q, v)\n\t}\n", p.Name, p.Name))
			}
		}

		sb.WriteString("\n\tfullURL := fmt.Sprintf(\"%s%s\", c.BaseURL, path)\n\tif len(query) > 0 {\n\t\tfullURL += \"?\" + query.Encode()\n\t}\n\n")

		if ep.HasBody {
			sb.WriteString(fmt.Sprintf("\treturn c.do(ctx, %q, fullURL, body)\n", ep.Method))
		} else {
			sb.WriteString(fmt.Sprintf("\treturn c.do(ctx, %q, fullURL, nil)\n", ep.Method))
		}

		sb.WriteString("}\n")
	}

	os.WriteFile(filePath, []byte(sb.String()), 0644)
}

func generateClient(outputDir string, grouped map[string][]Endpoint) {
	// Write base client
	writeBaseClient(outputDir)

	// Write per-service files
	for service, endpoints := range grouped {
		generateClientFile(outputDir, service, endpoints)
	}
}

func writeBaseClient(outputDir string) {
	filePath := filepath.Join(outputDir, "client.go")
	content := `// Code generated by scripts/generate/main.go. DO NOT EDIT.
package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Version is set at build time via ldflags.
var Version = "dev"

// Client is a typed HTTP client for the Nullify API.
type Client struct {
	BaseURL       string
	Token         string
	DefaultParams map[string]string
	HTTPClient    *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client on the API client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.HTTPClient = hc }
}

// NewClient creates a new Nullify API client.
func NewClient(host string, token string, defaultParams map[string]string, opts ...ClientOption) *Client {
	apiHost := host
	if !strings.HasPrefix(host, "api.") {
		apiHost = "api." + host
	}
	c := &Client{
		BaseURL:       "https://" + apiHost,
		Token:         token,
		DefaultParams: defaultParams,
		HTTPClient:    &http.Client{},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) do(ctx context.Context, method, url string, body io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("User-Agent", "Nullify-CLI/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
`
	os.WriteFile(filePath, []byte(content), 0644)
}

func generateCommands(outputDir string, grouped map[string][]Endpoint) {
	for service, endpoints := range grouped {
		generateCommandFile(outputDir, service, endpoints)
	}
}

func generateCommandFile(outputDir string, service string, endpoints []Endpoint) {
	filePath := filepath.Join(outputDir, service+".go")

	needsIO := false
	for _, ep := range endpoints {
		if ep.HasBody {
			needsIO = true
			break
		}
	}

	var sb strings.Builder
	sb.WriteString("// Code generated by scripts/generate/main.go. DO NOT EDIT.\npackage commands\n\nimport (\n\t\"net/url\"\n")
	if needsIO {
		sb.WriteString("\t\"os\"\n")
	}
	sb.WriteString("\n\t\"github.com/nullify-platform/cli/internal/api\"\n\t\"github.com/nullify-platform/cli/internal/output\"\n\t\"github.com/spf13/cobra\"\n\t\"github.com/spf13/pflag\"\n)\n\n")

	svcPascal := toPascalCase(service)
	svcDesc := serviceDescriptions[service]
	if svcDesc == "" {
		svcDesc = svcPascal + " commands"
	}
	sb.WriteString(fmt.Sprintf("func Register%sCommands(parent *cobra.Command, getClient func() *api.Client) {\n", svcPascal))
	sb.WriteString(fmt.Sprintf("\tserviceCmd := &cobra.Command{\n\t\tUse:   %q,\n\t\tShort: %q,\n\t}\n\tparent.AddCommand(serviceCmd)\n\n", service, svcDesc))

	for _, ep := range endpoints {
		cobraUse := generateCobraUse(ep)
		summary := strings.ReplaceAll(ep.Summary, `"`, `\"`)

		// Collect path and query params
		var pathParamName string
		var queryParams []Parameter
		for _, p := range ep.Parameters {
			if p.In == "path" {
				pathParamName = p.Name
			}
			if p.In == "query" {
				queryParams = append(queryParams, p)
			}
		}

		sb.WriteString("\t{\n")
		sb.WriteString(fmt.Sprintf("\t\tcmd := &cobra.Command{\n\t\t\tUse:   %q,\n\t\t\tShort: %q,\n", cobraUse, summary))

		if pathParamName != "" {
			sb.WriteString(fmt.Sprintf("\t\t\tArgs: cobra.MaximumNArgs(1),\n"))
		}

		sb.WriteString("\t\t\tRunE: func(cmd *cobra.Command, args []string) error {\n")
		sb.WriteString("\t\t\t\tclient := getClient()\n")
		sb.WriteString("\t\t\t\tparams := url.Values{}\n")

		// Build a flag name → API param name mapping for kebab-case translation
		hasKebabFlags := false
		for _, p := range queryParams {
			kebab := toKebabCase(p.Name)
			if kebab != p.Name {
				hasKebabFlags = true
				break
			}
		}

		if hasKebabFlags {
			sb.WriteString("\t\t\t\tflagMap := map[string]string{\n")
			for _, p := range queryParams {
				kebab := toKebabCase(p.Name)
				if kebab != p.Name {
					sb.WriteString(fmt.Sprintf("\t\t\t\t\t%q: %q,\n", kebab, p.Name))
				}
			}
			sb.WriteString("\t\t\t\t}\n")
			sb.WriteString("\t\t\t\tcmd.Flags().Visit(func(f *pflag.Flag) {\n\t\t\t\t\tif apiName, ok := flagMap[f.Name]; ok {\n\t\t\t\t\t\tparams.Set(apiName, f.Value.String())\n\t\t\t\t\t} else {\n\t\t\t\t\t\tparams.Set(f.Name, f.Value.String())\n\t\t\t\t\t}\n\t\t\t\t})\n")
		} else {
			sb.WriteString("\t\t\t\tcmd.Flags().Visit(func(f *pflag.Flag) {\n\t\t\t\t\tparams.Set(f.Name, f.Value.String())\n\t\t\t\t})\n")
		}

		if pathParamName != "" {
			sb.WriteString(fmt.Sprintf("\t\t\t\tif len(args) > 0 {\n\t\t\t\t\tparams.Set(%q, args[0])\n\t\t\t\t}\n", pathParamName))
		}

		if ep.HasBody {
			sb.WriteString(fmt.Sprintf("\t\t\t\tresult, err := client.%s(cmd.Context(), params, os.Stdin)\n", ep.FuncName))
		} else {
			sb.WriteString(fmt.Sprintf("\t\t\t\tresult, err := client.%s(cmd.Context(), params)\n", ep.FuncName))
		}

		sb.WriteString("\t\t\t\tif err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n")
		sb.WriteString("\t\t\t\treturn output.Print(cmd, result)\n")
		sb.WriteString("\t\t\t},\n\t\t}\n")

		for _, p := range queryParams {
			desc := strings.ReplaceAll(p.Description, `"`, `\"`)
			flagName := toKebabCase(p.Name)
			fmt.Fprintf(&sb, "\t\tcmd.Flags().String(%q, \"\", %q)\n", flagName, desc)
		}

		sb.WriteString("\t\tserviceCmd.AddCommand(cmd)\n\t}\n\n")
	}

	sb.WriteString("}\n")

	os.WriteFile(filePath, []byte(sb.String()), 0644)
}

func generateCobraUse(ep Endpoint) string {
	// Extract the last meaningful segment as the command name
	parts := strings.Split(ep.Path, "/")
	var lastNonParam string
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" && !strings.HasPrefix(parts[i], "{") {
			lastNonParam = parts[i]
			break
		}
	}

	// Determine action from HTTP method
	action := ""
	hasID := false
	for _, part := range parts {
		if strings.HasPrefix(part, "{") {
			hasID = true
		}
	}

	switch ep.Method {
	case "GET":
		if hasID {
			action = "get"
		} else {
			action = "list"
		}
	case "POST":
		action = "create"
	case "PUT":
		action = "update"
	case "PATCH":
		action = "patch"
	case "DELETE":
		action = "delete"
	}

	if lastNonParam == "" {
		return action
	}

	return fmt.Sprintf("%s-%s", action, lastNonParam)
}
