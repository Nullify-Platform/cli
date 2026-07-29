// generate reads the OpenAPI bundle and produces a typed Go API client and
// cobra command files for the CLI. The bundle is vendored at spec/ from a
// pinned monorepo commit (see `make fetch-spec`).
//
// Usage: go run ./scripts/generate/main.go --spec spec/nullify-openapi-bundle.yaml
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
	Ref                  string     `yaml:"$ref"`
	Type                 string     `yaml:"type"`
	Format               string     `yaml:"format"`
	Description          string     `yaml:"description"`
	Nullable             bool       `yaml:"nullable"`
	Enum                 []string   `yaml:"enum"`
	Items                *SchemaRef `yaml:"items"`
	AdditionalProperties *SchemaRef `yaml:"additionalProperties"`
}

type Schema struct {
	Type                 string               `yaml:"type"`
	Description          string               `yaml:"description"`
	Properties           map[string]SchemaRef `yaml:"properties"`
	Required             []string             `yaml:"required"`
	Enum                 []string             `yaml:"enum"`
	Nullable             bool                 `yaml:"nullable"`
	Format               string               `yaml:"format"`
	Items                *SchemaRef           `yaml:"items"`
	AdditionalProperties *SchemaRef           `yaml:"additionalProperties"`
	// Polymorphism keywords — none used by the current bundle. Parsed only so
	// generator-time assertions can fail loudly if a future spec drift introduces
	// them, preventing silent fallback to weak typing.
	OneOf         []SchemaRef `yaml:"oneOf"`
	AnyOf         []SchemaRef `yaml:"anyOf"`
	AllOf         []SchemaRef `yaml:"allOf"`
	Discriminator *struct {
		PropertyName string `yaml:"propertyName"`
	} `yaml:"discriminator"`
}

// Service grouping based on path prefix.
//
// NOTE: prefixes are matched against the full request path, so any path whose
// prefix is absent here is silently dropped from the generated CLI. Keep this in
// sync with the services published in the OpenAPI bundle.
var serviceMapping = map[string]string{
	"/sast/":           "sast",
	"/sca/":            "sca",
	"/secrets/":        "secrets",
	"/dast/":           "dast",
	"/admin/":          "admin",
	"/manager/":        "manager",
	"/context/":        "context",
	"/cspm/":           "cspm",
	"/scpm/":           "scpm",
	"/orchestrator/":   "orchestrator",
	"/asset-graph/":    "asset-graph",
	"/infrastructure/": "infrastructure",
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
	"context":        "Repository and Code Classification",
	"cspm":           "Cloud Security Posture Management (CSPM)",
	"scpm":           "SaaS Security Posture Management (SCPM)",
	"orchestrator":   "Scan Orchestration (autofix batches, code reviews, retriage, onboarding)",
	"asset-graph":    "Asset Graph (reachability, search, subgraph, summary)",
	"infrastructure": "Infrastructure Graphs",
	"ticket":         "Ticket Integration",
}

// Paths to exclude from CLI generation.
//
// Prefer this list over silent absence from serviceMapping: a path whose prefix
// is in neither map is dropped anyway, but listing it here records the intent
// so a future spec audit doesn't rediscover it as a "missing service".
// These are all paths the published bundle does carry but that aren't useful
// CLI commands: /auth/* are the auth handshake endpoints (access/refresh/github
// tokens, logout) the CLI drives through internal/auth, and /core/{bitbucket,jira}/*
// are integration webhooks/descriptors. Genuinely internal endpoints are kept
// out of the published bundle at the source (each service's openapi-public.yml),
// so they never reach here.
var excludePrefixes = []string{
	"/auth/",
	"/core/bitbucket/",
	"/core/jira/",
}

type Endpoint struct {
	Path         string
	Method       string
	Summary      string
	Description  string
	Service      string
	Parameters   []Parameter
	HasBody      bool
	BodySchema   string
	OutputSchema string
	FuncName     string
	CobraCmd     string
	CobraPath    string
	CobraUse     string // unique command name within its service (collision-disambiguated)
}

func main() {
	specPath := "spec/nullify-openapi-bundle.yaml"
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

	if err := assertSpecCompatible(spec); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	endpoints := extractEndpoints(spec)
	grouped := groupByService(endpoints)
	assignCobraUses(grouped)

	registry := buildModelRegistry(spec, endpoints)

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output dir: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cmdOutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating cmd output dir: %v\n", err)
		os.Exit(1)
	}

	generateModelsPackage(outputDir, registry)
	generateClient(outputDir, grouped, registry)
	generateCommands(cmdOutputDir, grouped, registry)

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

	// Sort fully deterministically. The spec's paths/methods are decoded from YAML
	// maps (random iteration order), so we must tie-break all the way down to the
	// method; otherwise two operations on the same path can swap order between runs
	// and produce spurious regeneration diffs (flaky drift checks).
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Service != endpoints[j].Service {
			return endpoints[i].Service < endpoints[j].Service
		}
		if endpoints[i].Path != endpoints[j].Path {
			return endpoints[i].Path < endpoints[j].Path
		}
		return endpoints[i].Method < endpoints[j].Method
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

var pathParamRegex = regexp.MustCompile(`\{([^}]+)\}`)

// extractPathParamNames returns the path parameter names from a path template
// in the order they appear in the URL.
func extractPathParamNames(path string) []string {
	matches := pathParamRegex.FindAllStringSubmatch(path, -1)
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m[1])
	}
	return names
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

func generateClient(outputDir string, grouped map[string][]Endpoint, registry *modelRegistry) {
	// Write base client
	writeBaseClient(outputDir)

	// Write per-service typed client files
	for service, endpoints := range grouped {
		emitTypedClient(outputDir, service, endpoints, registry)
	}
}

func writeBaseClient(outputDir string) {
	filePath := filepath.Join(outputDir, "client.go")
	content := `// Code generated by scripts/generate/main.go. DO NOT EDIT.
package api

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/apierror"
	"github.com/nullify-platform/cli/internal/client"
)

// Version is set at build time via ldflags.
var Version = "dev"

// defaultTimeout is the request timeout used when NULLIFY_HTTP_TIMEOUT is unset
// or invalid. 30s is too short for long-running calls (scan-start, autofix), so
// callers can raise it via the env var (e.g. "120s").
const defaultTimeout = 30 * time.Second

// httpTimeout returns the request timeout, overridable via the
// NULLIFY_HTTP_TIMEOUT env var (a Go duration string such as "120s").
func httpTimeout() time.Duration {
	if v := os.Getenv("NULLIFY_HTTP_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return defaultTimeout
}

// Client is a typed HTTP client for the Nullify API.
type Client struct {
	BaseURL       string
	Token         string
	DefaultParams map[string]string
	HTTPClient    *http.Client
}

// ClientOption configures a Client.
type ClientOption func(*Client)

// WithHTTPClient sets a custom HTTP client on the API client, overriding the
// default retrying client.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.HTTPClient = hc }
}

// NewClient creates a new Nullify API client. By default it retries on 429 and
// 5xx responses (callers get retries without passing WithHTTPClient).
func NewClient(host string, token string, defaultParams map[string]string, opts ...ClientOption) *Client {
	apiHost := host
	if !strings.HasPrefix(host, "api.") {
		apiHost = "api." + host
	}
	c := &Client{
		BaseURL:       "https://" + apiHost,
		Token:         token,
		DefaultParams: defaultParams,
		HTTPClient: &http.Client{
			Timeout:   httpTimeout(),
			Transport: client.NewRetryTransport(http.DefaultTransport),
		},
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, apierror.HandleError(resp)
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}

	return respBody, nil
}
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file %s: %v\n", filePath, err)
		os.Exit(1)
	}
}

func generateCommands(outputDir string, grouped map[string][]Endpoint, registry *modelRegistry) {
	for service, endpoints := range grouped {
		generateCommandFile(outputDir, service, endpoints, registry)
	}
}

func generateCommandFile(outputDir string, service string, endpoints []Endpoint, registry *modelRegistry) {
	filePath := filepath.Join(outputDir, service+".go")

	var sb strings.Builder
	sb.WriteString("// Code generated by scripts/generate/main.go. DO NOT EDIT.\npackage commands\n\nimport (\n")
	sb.WriteString("\t\"encoding/json\"\n")
	sb.WriteString("\t\"fmt\"\n")
	sb.WriteString("\t\"os\"\n")
	sb.WriteString("\t\"strconv\"\n")
	sb.WriteString("\t\"strings\"\n\n")
	sb.WriteString("\t\"github.com/nullify-platform/cli/internal/api\"\n")
	sb.WriteString("\t\"github.com/nullify-platform/cli/internal/api/models\"\n")
	sb.WriteString("\t\"github.com/nullify-platform/cli/internal/output\"\n")
	sb.WriteString("\t\"github.com/spf13/cobra\"\n)\n\n")
	// Suppress unused import warnings when a particular service file
	// happens not to need every import.
	sb.WriteString("var _ = json.Marshal\nvar _ = fmt.Errorf\nvar _ = os.Stdin\nvar _ = strconv.Atoi\nvar _ = strings.Split\nvar _ = models.RequestScope{}\n\n")

	svcPascal := toPascalCase(service)
	svcDesc := serviceDescriptions[service]
	if svcDesc == "" {
		svcDesc = svcPascal + " commands"
	}
	fmt.Fprintf(&sb, "func Register%sCommands(parent *cobra.Command, getClient func() *api.Client) {\n", svcPascal)
	fmt.Fprintf(&sb, "\tserviceCmd := &cobra.Command{\n\t\tUse:   %q,\n\t\tShort: %q,\n\t}\n\tparent.AddCommand(serviceCmd)\n\n", service, svcDesc)

	for _, ep := range endpoints {
		emitCobraCommand(&sb, ep, registry)
	}

	sb.WriteString("}\n")

	if err := os.WriteFile(filePath, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file %s: %v\n", filePath, err)
		os.Exit(1)
	}
}

// emitCobraCommand writes one cobra command block constructing a typed input,
// invoking the typed client method, and printing the typed response.
func emitCobraCommand(sb *strings.Builder, ep Endpoint, r *modelRegistry) {
	cobraUse := ep.CobraUse
	summary := strings.ReplaceAll(ep.Summary, `"`, `\"`)

	pathNames := extractPathParamNames(ep.Path)
	pathLookup := map[string]Parameter{}
	for _, p := range ep.Parameters {
		if p.In == "path" {
			pathLookup[p.Name] = p
		}
	}

	var queryParams []Parameter
	for _, p := range ep.Parameters {
		if p.In == "query" {
			if _, scope := requestScopeParams[p.Name]; scope {
				continue
			}
			queryParams = append(queryParams, p)
		}
	}
	sort.Slice(queryParams, func(i, j int) bool { return queryParams[i].Name < queryParams[j].Name })

	sb.WriteString("\t{\n")
	useStr := cobraUse
	for _, name := range pathNames {
		useStr += " <" + name + ">"
	}
	fmt.Fprintf(sb, "\t\tcmd := &cobra.Command{\n\t\t\tUse:   %q,\n\t\t\tShort: %q,\n", useStr, summary)
	if ep.HasBody && ep.BodySchema != "" {
		fmt.Fprintf(sb, "\t\t\tLong: %q,\n", bodyHelpText(ep, r))
	}
	if len(pathNames) > 0 {
		fmt.Fprintf(sb, "\t\t\tArgs:  cobra.ExactArgs(%d),\n", len(pathNames))
	}
	sb.WriteString("\t\t\tRunE: func(cmd *cobra.Command, args []string) error {\n")
	sb.WriteString("\t\t\t\tclient := getClient()\n")
	fmt.Fprintf(sb, "\t\t\t\tin := api.%s{}\n", inputStructName(ep))

	// Body resolution (before path/query overrides so the latter win):
	//   --data wins, else --data-file (- for stdin), else piped stdin fallback.
	if ep.HasBody && ep.BodySchema != "" {
		sb.WriteString("\t\t\t\tdataFlag, _ := cmd.Flags().GetString(\"data\")\n")
		sb.WriteString("\t\t\t\tdataFile, _ := cmd.Flags().GetString(\"data-file\")\n")
		sb.WriteString("\t\t\t\tswitch {\n")
		sb.WriteString("\t\t\t\tcase dataFlag != \"\":\n")
		sb.WriteString("\t\t\t\t\tif err := json.NewDecoder(strings.NewReader(dataFlag)).Decode(&in); err != nil {\n\t\t\t\t\t\treturn fmt.Errorf(\"decode --data: %w\", err)\n\t\t\t\t\t}\n")
		sb.WriteString("\t\t\t\tcase dataFile == \"-\":\n")
		sb.WriteString("\t\t\t\t\tif err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {\n\t\t\t\t\t\treturn fmt.Errorf(\"decode --data-file stdin: %w\", err)\n\t\t\t\t\t}\n")
		sb.WriteString("\t\t\t\tcase dataFile != \"\":\n")
		sb.WriteString("\t\t\t\t\tf, err := os.Open(dataFile)\n")
		sb.WriteString("\t\t\t\t\tif err != nil {\n\t\t\t\t\t\treturn fmt.Errorf(\"open --data-file: %w\", err)\n\t\t\t\t\t}\n")
		sb.WriteString("\t\t\t\t\tdec := json.NewDecoder(f)\n")
		sb.WriteString("\t\t\t\t\tdecErr := dec.Decode(&in)\n")
		sb.WriteString("\t\t\t\t\tf.Close()\n")
		sb.WriteString("\t\t\t\t\tif decErr != nil {\n\t\t\t\t\t\treturn fmt.Errorf(\"decode --data-file: %w\", decErr)\n\t\t\t\t\t}\n")
		sb.WriteString("\t\t\t\tdefault:\n")
		sb.WriteString("\t\t\t\t\tif stat, _ := os.Stdin.Stat(); (stat.Mode() & os.ModeCharDevice) == 0 {\n")
		sb.WriteString("\t\t\t\t\t\tif err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {\n\t\t\t\t\t\t\treturn fmt.Errorf(\"decode body from stdin: %w\", err)\n\t\t\t\t\t\t}\n")
		sb.WriteString("\t\t\t\t\t}\n")
		sb.WriteString("\t\t\t\t}\n")
	}

	// Path params from positional args.
	for i, name := range pathNames {
		p := pathLookup[name]
		f := fieldName(name)
		switch pathParamGoType(p) {
		case "int64":
			fmt.Fprintf(sb, "\t\t\t\tif v, err := strconv.ParseInt(args[%d], 10, 64); err != nil {\n\t\t\t\t\treturn fmt.Errorf(%q+\": %%w\", err)\n\t\t\t\t} else {\n\t\t\t\t\tin.%s = v\n\t\t\t\t}\n", i, name, f)
		case "int":
			fmt.Fprintf(sb, "\t\t\t\tif v, err := strconv.Atoi(args[%d]); err != nil {\n\t\t\t\t\treturn fmt.Errorf(%q+\": %%w\", err)\n\t\t\t\t} else {\n\t\t\t\t\tin.%s = v\n\t\t\t\t}\n", i, name, f)
		default:
			fmt.Fprintf(sb, "\t\t\t\tin.%s = args[%d]\n", f, i)
		}
	}

	// Query params from flags.
	for _, p := range queryParams {
		emitFlagToInput(sb, p, r)
	}

	if ep.OutputSchema != "" {
		fmt.Fprintf(sb, "\t\t\t\tout, err := client.%s(cmd.Context(), in)\n", ep.FuncName)
		sb.WriteString("\t\t\t\tif err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n")
		sb.WriteString("\t\t\t\tdata, err := json.Marshal(out)\n\t\t\t\tif err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n")
		sb.WriteString("\t\t\t\treturn output.Print(cmd, data)\n")
	} else {
		fmt.Fprintf(sb, "\t\t\t\tdata, err := client.%s(cmd.Context(), in)\n", ep.FuncName)
		sb.WriteString("\t\t\t\tif err != nil {\n\t\t\t\t\treturn err\n\t\t\t\t}\n")
		sb.WriteString("\t\t\t\treturn output.Print(cmd, data)\n")
	}
	sb.WriteString("\t\t\t},\n\t\t}\n")

	// Flag declarations.
	for _, p := range queryParams {
		desc := strings.ReplaceAll(p.Description, `"`, `\"`)
		flagName := toKebabCase(p.Name)
		fmt.Fprintf(sb, "\t\tcmd.Flags().String(%q, \"\", %q)\n", flagName, desc)
	}
	if ep.HasBody && ep.BodySchema != "" {
		sb.WriteString("\t\tcmd.Flags().String(\"data\", \"\", \"Request body as a raw JSON string\")\n")
		sb.WriteString("\t\tcmd.Flags().String(\"data-file\", \"\", \"Read request body JSON from a file (- for stdin)\")\n")
	}

	sb.WriteString("\t\tserviceCmd.AddCommand(cmd)\n\t}\n\n")
}

// bodyHelpText builds the cobra Long text for a body-bearing endpoint by
// surfacing the top-level properties of the request schema, so users can
// discover the body shape from --help instead of digging through the spec.
// Falls back to a generic note when the schema is missing or has no top-level
// properties (e.g. a $ref to a primitive or alias).
func bodyHelpText(ep Endpoint, r *modelRegistry) string {
	const usage = "\n\nProvide the body with --data '<json>', --data-file <path> (- for stdin), or piped stdin."
	s, ok := r.schemas[ep.BodySchema]
	if !ok || len(s.Properties) == 0 {
		return "Request body: raw JSON." + usage
	}
	required := map[string]bool{}
	for _, n := range s.Required {
		required[n] = true
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		ref := s.Properties[n]
		part := n + " (" + jsonTypeHint(ref)
		if required[n] {
			part += ", required"
		}
		part += ")"
		parts = append(parts, part)
	}
	return "Request body (JSON) fields: " + strings.Join(parts, ", ") + "." + usage
}

// jsonTypeHint returns a short JSON-style type label for a SchemaRef, suitable
// for use in cobra help text. Falls back to "object" for $refs (which point to
// a component schema, almost always a struct) and for unknown shapes.
func jsonTypeHint(ref SchemaRef) string {
	if ref.Ref != "" {
		return "object"
	}
	switch ref.Type {
	case "string", "integer", "number", "boolean", "array", "object":
		return ref.Type
	default:
		return "object"
	}
}

// emitFlagToInput writes the code that copies one flag value into the typed
// input struct, with type conversion. Errors during conversion abort the
// command with a clear message.
func emitFlagToInput(sb *strings.Builder, p Parameter, r *modelRegistry) {
	f := fieldName(p.Name)
	flagName := toKebabCase(p.Name)
	typ := r.queryParamGoType(p, "models.")

	switch {
	case strings.HasPrefix(typ, "[]"):
		// Slice flags arrive as a single comma-separated string for now (CLI
		// commands historically pass a single value); split on comma.
		inner := strings.TrimPrefix(typ, "[]")
		switch inner {
		case "int64":
			fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tfor _, s := range strings.Split(v, \",\") {\n\t\t\t\t\t\tif n, err := strconv.ParseInt(s, 10, 64); err == nil {\n\t\t\t\t\t\t\tin.%s = append(in.%s, n)\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n", flagName, f, f)
		default:
			fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tfor _, s := range strings.Split(v, \",\") {\n\t\t\t\t\t\tin.%s = append(in.%s, %s(s))\n\t\t\t\t\t}\n\t\t\t\t}\n", flagName, f, f, inner)
		}
	case typ == "int64":
		fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tif n, err := strconv.ParseInt(v, 10, 64); err != nil {\n\t\t\t\t\t\treturn fmt.Errorf(%q+\": %%w\", err)\n\t\t\t\t\t} else {\n\t\t\t\t\t\tx := n\n\t\t\t\t\t\tin.%s = &x\n\t\t\t\t\t}\n\t\t\t\t}\n", flagName, p.Name, f)
	case typ == "int" || typ == "int32":
		fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tif n, err := strconv.Atoi(v); err != nil {\n\t\t\t\t\t\treturn fmt.Errorf(%q+\": %%w\", err)\n\t\t\t\t\t} else {\n\t\t\t\t\t\tx := %s(n)\n\t\t\t\t\t\tin.%s = &x\n\t\t\t\t\t}\n\t\t\t\t}\n", flagName, p.Name, typ, f)
	case typ == "bool":
		fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tb := v == \"true\"\n\t\t\t\t\tin.%s = &b\n\t\t\t\t}\n", flagName, f)
	case typ == "float64":
		fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tif n, err := strconv.ParseFloat(v, 64); err != nil {\n\t\t\t\t\t\treturn fmt.Errorf(%q+\": %%w\", err)\n\t\t\t\t\t} else {\n\t\t\t\t\t\tx := n\n\t\t\t\t\t\tin.%s = &x\n\t\t\t\t\t}\n\t\t\t\t}\n", flagName, p.Name, f)
	default:
		// String (incl. typed-string enums). The field is *T (optional), so
		// dereference is needed; use a temp.
		fmt.Fprintf(sb, "\t\t\t\tif v, _ := cmd.Flags().GetString(%q); v != \"\" {\n\t\t\t\t\tx := %s(v)\n\t\t\t\t\tin.%s = &x\n\t\t\t\t}\n", flagName, typ, f)
	}
}

// pathSegments returns the non-empty, non-parameter segments of a path.
func pathSegments(path string) []string {
	var segs []string
	for _, part := range strings.Split(path, "/") {
		if part == "" || strings.HasPrefix(part, "{") {
			continue
		}
		segs = append(segs, part)
	}
	return segs
}

// cobraAction maps an HTTP method (and whether the path has a path parameter) to
// the verb prefix used in command names.
func cobraAction(ep Endpoint) string {
	hasID := len(extractPathParamNames(ep.Path)) > 0
	switch ep.Method {
	case "GET":
		if hasID {
			return "get"
		}
		return "list"
	case "POST":
		return "create"
	case "PUT":
		return "update"
	case "PATCH":
		return "patch"
	case "DELETE":
		return "delete"
	}
	return ""
}

// generateCobraUse builds the short command name from the action and the last
// meaningful path segment (e.g. GET /sast/findings -> "list-findings"). It can
// collide across endpoints that differ only by an intermediate segment
// (e.g. /dast/pentest/scans and /dast/bughunt/scans both -> "list-scans");
// assignCobraUses disambiguates those.
func generateCobraUse(ep Endpoint) string {
	segs := pathSegments(ep.Path)
	action := cobraAction(ep)
	if len(segs) == 0 {
		return action
	}
	name := fmt.Sprintf("%s-%s", action, segs[len(segs)-1])
	// When the path has a parameter and method is POST, append "-by-id" to avoid
	// collisions with batch endpoints (e.g. POST /findings/allowlist vs
	// POST /findings/{id}/allowlist).
	if len(extractPathParamNames(ep.Path)) > 0 && ep.Method == "POST" {
		name += "-by-id"
	}
	return name
}

// disambiguatedUse builds a fully-qualified command name from every non-service
// path segment, used when the short name collides with another endpoint in the
// same service (e.g. /dast/pentest/scans -> "list-pentest-scans").
func disambiguatedUse(ep Endpoint) string {
	segs := pathSegments(ep.Path)
	// Drop the leading service segment; the service is already the cobra parent.
	if len(segs) > 1 {
		segs = segs[1:]
	}
	action := cobraAction(ep)
	name := action + "-" + strings.Join(segs, "-")
	if len(extractPathParamNames(ep.Path)) > 0 && ep.Method == "POST" {
		name += "-by-id"
	}
	return name
}

// assignCobraUses sets a unique CobraUse on every endpoint within each service.
// Non-colliding endpoints keep the short name; colliding ones are expanded to
// include their distinguishing path segments, and any residual duplicates get a
// numeric suffix as a last resort. This guarantees no two commands under one
// service parent share a Use (which would silently shadow each other in cobra).
func assignCobraUses(grouped map[string][]Endpoint) {
	for _, endpoints := range grouped {
		base := make([]string, len(endpoints))
		counts := map[string]int{}
		for i := range endpoints {
			base[i] = generateCobraUse(endpoints[i])
			counts[base[i]]++
		}
		seen := map[string]int{}
		for i := range endpoints {
			use := base[i]
			if counts[use] > 1 {
				use = disambiguatedUse(endpoints[i])
			}
			if n := seen[use]; n > 0 {
				seen[use] = n + 1
				use = fmt.Sprintf("%s-%d", use, n+1)
			} else {
				seen[use] = 1
			}
			endpoints[i].CobraUse = use
		}
	}
}
