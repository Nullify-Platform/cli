// Typed-client generator: schema closure, models emitter, and typed method
// emitter. Companion to main.go.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// requestScopeParams is the set of tenant-scoping query params that appear on
// nearly every endpoint. They're folded into a shared models.RequestScope
// struct rather than duplicated on every per-endpoint input struct. The set is
// detected by *name* because the spec doesn't factor them as reusable
// parameters; each endpoint repeats the full definition inline.
var requestScopeParams = map[string]struct{}{
	"installationId":        {},
	"githubOwnerId":         {},
	"gitlabGroupId":         {},
	"azureOrganizationId":   {},
	"bitbucketWorkspaceId":  {},
	"azureRepositoryId":     {},
	"githubRepositoryId":    {},
	"bitbucketRepositoryId": {},
	"githubTeamId":          {},
}

// modelRegistry tracks every schema reachable from the kept endpoint surface,
// along with the set of services that own it. owners drives the per-service
// file split: schemas with |owners|>1 go in models/common.go, others go in
// models/<svc>.go.
type modelRegistry struct {
	schemas   map[string]Schema
	reachable map[string]struct{}
	owners    map[string]map[string]struct{}
}

func newModelRegistry(spec OpenAPISpec) *modelRegistry {
	return &modelRegistry{
		schemas:   spec.Components.Schemas,
		reachable: map[string]struct{}{},
		owners:    map[string]map[string]struct{}{},
	}
}

func (r *modelRegistry) markOwner(name, service string) {
	if r.owners[name] == nil {
		r.owners[name] = map[string]struct{}{}
	}
	r.owners[name][service] = struct{}{}
}

// walkRef adds a schema (by name) to the reachable set if not already present
// and recursively walks its properties for further refs.
func (r *modelRegistry) walkRef(name, service string) {
	if name == "" {
		return
	}
	r.markOwner(name, service)
	if _, seen := r.reachable[name]; seen {
		return
	}
	r.reachable[name] = struct{}{}
	s, ok := r.schemas[name]
	if !ok {
		return
	}
	r.walkSchema(s, service)
}

func (r *modelRegistry) walkSchema(s Schema, service string) {
	for _, p := range s.Properties {
		r.walkSchemaRef(p, service)
	}
	if s.Items != nil {
		r.walkSchemaRef(*s.Items, service)
	}
	if s.AdditionalProperties != nil {
		r.walkSchemaRef(*s.AdditionalProperties, service)
	}
}

func (r *modelRegistry) walkSchemaRef(ref SchemaRef, service string) {
	if ref.Ref != "" {
		r.walkRef(extractSchemaName(ref.Ref), service)
		return
	}
	if ref.Items != nil {
		r.walkSchemaRef(*ref.Items, service)
	}
	if ref.AdditionalProperties != nil {
		r.walkSchemaRef(*ref.AdditionalProperties, service)
	}
}

// buildModelRegistry walks every kept endpoint, seeds the closure from
// request/response/parameter refs, and transitively follows refs through
// schema properties, items, and additionalProperties.
func buildModelRegistry(spec OpenAPISpec, endpoints []Endpoint) *modelRegistry {
	r := newModelRegistry(spec)
	for _, ep := range endpoints {
		// Body schema seeds.
		if ep.BodySchema != "" {
			r.walkRef(ep.BodySchema, ep.Service)
		}
		// Response schema seeds (only 2xx for now; non-2xx is uniformly
		// RestErrResponse and we surface it via the apierror package).
		if ep.OutputSchema != "" {
			r.walkRef(ep.OutputSchema, ep.Service)
		}
		// Parameter schema seeds (some params use $ref to a typed enum, e.g.
		// severity → ModelsSeverity).
		for _, p := range ep.Parameters {
			r.walkSchemaRef(p.Schema, ep.Service)
		}
	}
	return r
}

// assertSpecCompatible fails the build if the spec contains constructs the
// generator can't represent in strongly-typed Go. This is deliberate: the
// alternative is silent fallback to weak typing (the io.Reader / []byte that
// allowed the PR #152 start_pentest bug to ship).
func assertSpecCompatible(spec OpenAPISpec) error {
	var errs []string
	for name, s := range spec.Components.Schemas {
		if len(s.OneOf) > 0 {
			errs = append(errs, fmt.Sprintf("schema %q uses oneOf (polymorphism)", name))
		}
		if len(s.AnyOf) > 0 {
			errs = append(errs, fmt.Sprintf("schema %q uses anyOf", name))
		}
		if len(s.AllOf) > 0 {
			errs = append(errs, fmt.Sprintf("schema %q uses allOf", name))
		}
		if s.Discriminator != nil {
			errs = append(errs, fmt.Sprintf("schema %q uses discriminator", name))
		}
		if s.Type == "integer" && len(s.Enum) > 0 {
			errs = append(errs, fmt.Sprintf("schema %q is an integer enum (only string enums supported)", name))
		}
	}
	for path, methods := range spec.Paths {
		for method, op := range methods {
			if op.RequestBody != nil {
				for ct, body := range op.RequestBody.Content {
					if ct != "application/json" {
						errs = append(errs, fmt.Sprintf("%s %s requestBody content-type %q (only application/json supported)", method, path, ct))
					}
					if body.Schema.Ref == "" && body.Schema.Type == "" {
						errs = append(errs, fmt.Sprintf("%s %s requestBody has no schema", method, path))
					}
				}
			}
			for status, resp := range op.Responses {
				for ct, content := range resp.Content {
					if ct != "application/json" && ct != "application/xml" && ct != "text/plain" {
						errs = append(errs, fmt.Sprintf("%s %s response %s content-type %q unsupported", method, path, status, ct))
					}
					_ = content
				}
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	sort.Strings(errs)
	return fmt.Errorf("spec compatibility check failed:\n  - %s", strings.Join(errs, "\n  - "))
}

// goType resolves a SchemaRef to its Go type string. The prefix argument is
// the package qualifier used for $refs to component schemas — pass "models."
// from outside the models package, and "" from inside. For primitives it
// returns the Go primitive. For arrays/maps it recurses. Pointer wrapping for
// optionality is applied by the caller (goFieldType) — goType itself returns
// the value type.
func (r *modelRegistry) goType(ref SchemaRef, prefix string) string {
	if ref.Ref != "" {
		return prefix + extractSchemaName(ref.Ref)
	}
	switch ref.Type {
	case "string":
		return "string"
	case "integer":
		switch ref.Format {
		case "int64":
			return "int64"
		case "int32":
			return "int32"
		default:
			return "int"
		}
	case "number":
		return "float64"
	case "boolean":
		return "bool"
	case "array":
		if ref.Items == nil {
			return "[]json.RawMessage"
		}
		return "[]" + r.goType(*ref.Items, prefix)
	case "object":
		if ref.AdditionalProperties != nil {
			return "map[string]" + r.goType(*ref.AdditionalProperties, prefix)
		}
		return "map[string]json.RawMessage"
	case "":
		return "json.RawMessage"
	}
	return "json.RawMessage"
}

// goFieldType wraps goType with the pointer rule:
//   - required + non-nullable → T
//   - everything else        → *T (so optional fields can be omitted via
//     omitempty AND nullable can be expressed as nil)
//
// Slices and maps express absence natively (empty == omitted under omitempty);
// they're never wrapped in a pointer.
func (r *modelRegistry) goFieldType(ref SchemaRef, required bool, prefix string) string {
	base := r.goType(ref, prefix)
	if strings.HasPrefix(base, "[]") || strings.HasPrefix(base, "map[") {
		return base
	}
	if required && !ref.Nullable {
		return base
	}
	return "*" + base
}

// jsonTag builds a `json:"name,omitempty"` tag string for a struct field. The
// omitempty rule mirrors the pointer rule: omit unless the field is
// required-and-non-nullable.
func jsonTag(name string, required, nullable bool) string {
	if required && !nullable {
		return fmt.Sprintf("`json:%q`", name)
	}
	return fmt.Sprintf("`json:\"%s,omitempty\"`", name)
}

// urlTag builds a `url:"name,omitempty" json:"-"` tag for a query-param field.
// The json:"-" prevents body-stdin unmarshalling from accidentally populating
// the field via case-insensitive name match (a JSON key "installationId" would
// otherwise match a Go field "InstallationID").
func urlTag(name string) string {
	return fmt.Sprintf("`url:\"%s,omitempty\" json:\"-\"`", name)
}

// pathTag builds a `path:"name" json:"-"` tag for a path-param field. The
// json:"-" suppresses accidental cross-pollution from body-stdin JSON.
func pathTag(name string) string {
	return fmt.Sprintf("`path:%q json:\"-\"`", name)
}

// fieldName converts a JSON property name to a Go-exported field name. Special
// cases the common ID suffixes so they render in canonical Go form (ID, not Id).
func fieldName(s string) string {
	pc := toPascalCase(s)
	// Canonical Go renderings for trailing acronyms.
	for _, suffix := range []string{"Id", "Url", "Uri", "Api", "Sast", "Sca", "Dast", "Cspm", "Scpm"} {
		if strings.HasSuffix(pc, suffix) {
			pc = pc[:len(pc)-len(suffix)] + strings.ToUpper(suffix)
		}
	}
	return pc
}

// emitStruct writes a Go struct declaration for a component schema. prefix is
// "" when emitting inside the models package, "models." when emitting outside.
func (r *modelRegistry) emitStruct(sb *strings.Builder, name string, s Schema, prefix string) {
	if s.Description != "" {
		writeDocComment(sb, name+" — "+s.Description)
	}
	fmt.Fprintf(sb, "type %s struct {\n", name)
	reqSet := map[string]struct{}{}
	for _, name := range s.Required {
		reqSet[name] = struct{}{}
	}
	// Stable field order.
	props := make([]string, 0, len(s.Properties))
	for p := range s.Properties {
		props = append(props, p)
	}
	sort.Strings(props)
	usedNames := map[string]int{}
	for _, p := range props {
		ref := s.Properties[p]
		_, required := reqSet[p]
		goName := fieldName(p)
		// Avoid Go field-name collisions when two JSON keys collapse to the same
		// PascalCase identifier after acronym-canonicalization (e.g. "id" and "ID"
		// both → "ID"). Suffix with an incrementing number.
		if n := usedNames[goName]; n > 0 {
			goName = fmt.Sprintf("%s%d", goName, n)
		}
		usedNames[fieldName(p)]++
		typ := r.goFieldType(ref, required, prefix)
		tag := jsonTag(p, required, ref.Nullable)
		fmt.Fprintf(sb, "\t%s %s %s\n", goName, typ, tag)
	}
	// Sentinel field forbidding collisions across schemas via empty struct names
	// is unnecessary; an empty schema is rare and emits a struct with no fields.
	if len(props) == 0 {
		// Empty struct — emit a placeholder underscore field to keep the type
		// distinct from json.RawMessage. Actually Go allows empty struct{}, so
		// just emit nothing inside.
		_ = props
	}
	sb.WriteString("}\n\n")
}

// emitEnum writes a named string type and a const block for an enum schema.
// Deduplicates constant names: when two enum values collapse to the same Go
// identifier (e.g. "Azure" and "AZURE" → "Azure"), only the first wins; later
// duplicates are emitted as Go comments to preserve the spec record without
// declaration collisions.
func emitEnum(sb *strings.Builder, name string, s Schema) {
	if s.Description != "" {
		writeDocComment(sb, name+" — "+s.Description)
	}
	fmt.Fprintf(sb, "type %s string\n\n", name)
	if len(s.Enum) == 0 {
		return
	}
	fmt.Fprintf(sb, "const (\n")
	seen := map[string]string{}
	for _, v := range s.Enum {
		suffix := enumConstSuffix(v)
		if suffix == "" {
			// Value with no representable Go identifier (e.g. all symbols).
			// Emit only the type declaration, not a const for this value.
			fmt.Fprintf(sb, "\t// (skipped value %q — no representable Go identifier)\n", v)
			continue
		}
		constName := name + suffix
		// Avoid colliding with the type name itself (zero-suffix or value == type).
		if constName == name {
			constName = name + "Value"
		}
		if prev, ok := seen[constName]; ok {
			fmt.Fprintf(sb, "\t// (duplicate %q collides with %q → %s)\n", v, prev, constName)
			continue
		}
		seen[constName] = v
		fmt.Fprintf(sb, "\t%s %s = %q\n", constName, name, v)
	}
	sb.WriteString(")\n\n")
}

// enumConstSuffix derives a Go constant suffix from an enum value string.
// "CRITICAL" → "Critical"; "user_fixed" → "UserFixed"; "in_progress_agent" →
// "InProgressAgent"; "C/C++" → "CCpp"; "C#" → "CSharp". Sanitizes to a valid
// Go identifier suffix; the result is appended to the type name to form the
// const name.
func enumConstSuffix(v string) string {
	// Common-language tokens with special characters get readable mappings.
	replacements := map[string]string{
		"C++":  "Cpp",
		"C#":   "CSharp",
		"F#":   "FSharp",
		".NET": "DotNet",
		"C/C":  "C",
	}
	for from, to := range replacements {
		v = strings.ReplaceAll(v, from, to)
	}
	// Anything that isn't a letter or digit becomes a separator.
	var spaced strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			spaced.WriteRune(r)
		} else {
			spaced.WriteRune(' ')
		}
	}
	words := strings.Fields(spaced.String())
	var out string
	for _, w := range words {
		runes := []rune(strings.ToLower(w))
		if len(runes) > 0 {
			runes[0] = []rune(strings.ToUpper(string(runes[0])))[0]
		}
		out += string(runes)
	}
	// If the value started with a digit, prefix V to keep it a valid Go ident.
	if out != "" && out[0] >= '0' && out[0] <= '9' {
		out = "V" + out
	}
	return out
}

// emitAlias writes a simple type alias for non-struct, non-enum schemas (e.g. a
// schema whose body is just `type: string`). Emitted inside the models package
// so refs to other models drop the "models." prefix.
func (r *modelRegistry) emitAlias(sb *strings.Builder, name string, s Schema) {
	ref := SchemaRef{Type: s.Type, Format: s.Format, Items: s.Items, AdditionalProperties: s.AdditionalProperties}
	fmt.Fprintf(sb, "type %s = %s\n\n", name, r.goType(ref, ""))
}

func writeDocComment(sb *strings.Builder, text string) {
	for _, line := range strings.Split(text, "\n") {
		fmt.Fprintf(sb, "// %s\n", line)
	}
}

// schemaUsesJSON returns true if a struct's field types reference
// json.RawMessage, requiring the encoding/json import.
func schemaUsesJSON(r *modelRegistry, s Schema) bool {
	for _, ref := range s.Properties {
		if strings.Contains(r.goType(ref, ""), "json.RawMessage") {
			return true
		}
	}
	if s.Items != nil && strings.Contains(r.goType(*s.Items, ""), "json.RawMessage") {
		return true
	}
	if s.AdditionalProperties != nil && strings.Contains(r.goType(*s.AdditionalProperties, ""), "json.RawMessage") {
		return true
	}
	return false
}

// generateModelsPackage writes the models package: common.go for schemas owned
// by >1 service (or shared types), and <svc>.go for service-local schemas.
func generateModelsPackage(outputDir string, r *modelRegistry) {
	modelsDir := filepath.Join(outputDir, "models")
	if err := os.MkdirAll(modelsDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating models dir: %v\n", err)
		os.Exit(1)
	}

	// Bucket reachable schemas by owning service set. Single-owner schemas go
	// in models/<svc>.go; multi-owner schemas go in models/common.go.
	type bucket struct {
		names []string
	}
	buckets := map[string]*bucket{} // service name OR "common"
	names := make([]string, 0, len(r.reachable))
	for n := range r.reachable {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		owners := r.owners[n]
		target := "common"
		if len(owners) == 1 {
			for o := range owners {
				target = o
			}
		}
		if buckets[target] == nil {
			buckets[target] = &bucket{}
		}
		buckets[target].names = append(buckets[target].names, n)
	}

	for bucketName, b := range buckets {
		writeModelsFile(modelsDir, bucketName, b.names, r)
	}

	// Always write a request_scope.go shipping the embedded RequestScope type.
	writeRequestScope(modelsDir)
}

func writeModelsFile(modelsDir, bucketName string, names []string, r *modelRegistry) {
	var sb strings.Builder
	sb.WriteString("// Code generated by scripts/generate/main.go. DO NOT EDIT.\npackage models\n\n")

	// Determine imports.
	needsJSON := false
	for _, n := range names {
		s := r.schemas[n]
		if s.Type == "object" || s.Type == "" {
			if schemaUsesJSON(r, s) {
				needsJSON = true
				break
			}
		}
	}
	if needsJSON {
		sb.WriteString("import \"encoding/json\"\n\n")
	}

	for _, n := range names {
		s := r.schemas[n]
		switch {
		case s.Type == "string" && len(s.Enum) > 0:
			emitEnum(&sb, n, s)
		case s.Type == "object" || s.Type == "":
			r.emitStruct(&sb, n, s, "")
		default:
			// Primitive alias (rare).
			r.emitAlias(&sb, n, s)
		}
	}

	fileName := bucketName + ".go"
	if err := os.WriteFile(filepath.Join(modelsDir, fileName), []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", fileName, err)
		os.Exit(1)
	}
}

// writeRequestScope writes the shared tenant-scoping struct embedded in every
// per-endpoint input. The 9 fields here mirror the inline query params that
// appear on nearly every operation in the spec.
func writeRequestScope(modelsDir string) {
	content := `// Code generated by scripts/generate/main.go. DO NOT EDIT.
package models

import (
	"net/url"
	"strconv"
)

// RequestScope carries the tenant/scope query parameters that appear on
// nearly every Nullify API endpoint. Embed it in any endpoint input struct
// and the generated client will encode set fields into the request URL.
//
// Most callers leave these zero and let the Client's DefaultParams (set at
// construction time from the CLI/MCP auth flow) supply the scope.
type RequestScope struct {
	InstallationID        string   ` + "`url:\"installationId,omitempty\" json:\"-\"`" + `
	GithubOwnerID         int64    ` + "`url:\"githubOwnerId,omitempty\" json:\"-\"`" + `
	GitlabGroupID         int64    ` + "`url:\"gitlabGroupId,omitempty\" json:\"-\"`" + `
	AzureOrganizationID   string   ` + "`url:\"azureOrganizationId,omitempty\" json:\"-\"`" + `
	BitbucketWorkspaceID  string   ` + "`url:\"bitbucketWorkspaceId,omitempty\" json:\"-\"`" + `
	AzureRepositoryID     []string ` + "`url:\"azureRepositoryId,omitempty\" json:\"-\"`" + `
	GithubRepositoryID    []int64  ` + "`url:\"githubRepositoryId,omitempty\" json:\"-\"`" + `
	BitbucketRepositoryID []string ` + "`url:\"bitbucketRepositoryId,omitempty\" json:\"-\"`" + `
	GithubTeamID          int64    ` + "`url:\"githubTeamId,omitempty\" json:\"-\"`" + `
}

// AddTo encodes set fields into a url.Values, using Add for slice fields so
// repeated query keys serialize correctly (azureRepositoryId=a&azureRepositoryId=b).
func (s RequestScope) AddTo(q url.Values) {
	if s.InstallationID != "" {
		q.Set("installationId", s.InstallationID)
	}
	if s.GithubOwnerID != 0 {
		q.Set("githubOwnerId", strconv.FormatInt(s.GithubOwnerID, 10))
	}
	if s.GitlabGroupID != 0 {
		q.Set("gitlabGroupId", strconv.FormatInt(s.GitlabGroupID, 10))
	}
	if s.AzureOrganizationID != "" {
		q.Set("azureOrganizationId", s.AzureOrganizationID)
	}
	if s.BitbucketWorkspaceID != "" {
		q.Set("bitbucketWorkspaceId", s.BitbucketWorkspaceID)
	}
	for _, v := range s.AzureRepositoryID {
		q.Add("azureRepositoryId", v)
	}
	for _, v := range s.GithubRepositoryID {
		q.Add("githubRepositoryId", strconv.FormatInt(v, 10))
	}
	for _, v := range s.BitbucketRepositoryID {
		q.Add("bitbucketRepositoryId", v)
	}
	if s.GithubTeamID != 0 {
		q.Set("githubTeamId", strconv.FormatInt(s.GithubTeamID, 10))
	}
}
`
	if err := os.WriteFile(filepath.Join(modelsDir, "request_scope.go"), []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing request_scope.go: %v\n", err)
		os.Exit(1)
	}
}

// --- Typed method emitter ------------------------------------------------

// emitTypedClient writes the per-service Go file containing the typed input
// structs and the typed methods on *Client. Replaces the legacy
// generateClientFile.
func emitTypedClient(outputDir, service string, endpoints []Endpoint, r *modelRegistry) {
	filePath := filepath.Join(outputDir, service+".go")

	var sb strings.Builder
	sb.WriteString("// Code generated by scripts/generate/main.go. DO NOT EDIT.\npackage api\n\n")
	sb.WriteString("import (\n")
	sb.WriteString("\t\"bytes\"\n")
	sb.WriteString("\t\"context\"\n")
	sb.WriteString("\t\"encoding/json\"\n")
	sb.WriteString("\t\"fmt\"\n")
	sb.WriteString("\t\"net/url\"\n")
	sb.WriteString("\t\"strconv\"\n")
	sb.WriteString("\t\"strings\"\n\n")
	sb.WriteString("\t\"github.com/nullify-platform/cli/internal/api/models\"\n")
	sb.WriteString(")\n\n")

	// Hush "imported and not used" if a particular service file happens to
	// not need one of these. The placeholders ensure every emitted file
	// compiles regardless of endpoint mix.
	sb.WriteString("var _ = bytes.NewReader\nvar _ = json.Marshal\nvar _ = strconv.FormatInt\nvar _ = strings.Replace\nvar _ = fmt.Sprintf\nvar _ = url.PathEscape\nvar _ = models.RequestScope{}\n\n")

	for _, ep := range endpoints {
		emitInputStruct(&sb, ep, r)
		emitMethod(&sb, ep, r)
	}

	if err := os.WriteFile(filePath, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing %s: %v\n", filePath, err)
		os.Exit(1)
	}
}

// inputStructName returns the Go type name for an endpoint's input struct
// (e.g. CreateDastPentestStartInput).
func inputStructName(ep Endpoint) string { return ep.FuncName + "Input" }

// emitInputStruct writes the per-endpoint input struct combining path
// parameters, query parameters, and body fields. The 9 tenant-scope query
// params are folded into an embedded models.RequestScope.
func emitInputStruct(sb *strings.Builder, ep Endpoint, r *modelRegistry) {
	hasScope := false
	for _, p := range ep.Parameters {
		if p.In == "query" {
			if _, ok := requestScopeParams[p.Name]; ok {
				hasScope = true
				break
			}
		}
	}

	if ep.Summary != "" {
		writeDocComment(sb, fmt.Sprintf("%s is the input for %s — %s.", inputStructName(ep), ep.FuncName, ep.Summary))
	} else {
		writeDocComment(sb, fmt.Sprintf("%s is the input for %s.", inputStructName(ep), ep.FuncName))
	}
	fmt.Fprintf(sb, "type %s struct {\n", inputStructName(ep))

	// Path params in URL order (deterministic).
	pathNames := extractPathParamNames(ep.Path)
	pathLookup := map[string]Parameter{}
	for _, p := range ep.Parameters {
		if p.In == "path" {
			pathLookup[p.Name] = p
		}
	}
	for _, pn := range pathNames {
		p := pathLookup[pn]
		typ := pathParamGoType(p)
		fmt.Fprintf(sb, "\t%s %s %s\n", fieldName(pn), typ, pathTag(pn))
	}

	// Non-scope query params, sorted by name.
	var queryParams []Parameter
	for _, p := range ep.Parameters {
		if p.In != "query" {
			continue
		}
		if _, scope := requestScopeParams[p.Name]; scope {
			continue
		}
		queryParams = append(queryParams, p)
	}
	sort.Slice(queryParams, func(i, j int) bool { return queryParams[i].Name < queryParams[j].Name })
	for _, p := range queryParams {
		// Query params are always optional from the client's perspective; we
		// emit them as *T (or []T for slices) so CLI/MCP callers can leave
		// them zero without sending empty-string defaults.
		typ := r.goFieldType(p.Schema, false, "models.")
		fmt.Fprintf(sb, "\t%s %s %s\n", fieldName(p.Name), typ, urlTag(p.Name))
	}

	// Body fields from the request body schema, if any.
	if ep.BodySchema != "" {
		if bs, ok := r.schemas[ep.BodySchema]; ok {
			reqSet := map[string]struct{}{}
			for _, name := range bs.Required {
				reqSet[name] = struct{}{}
			}
			props := make([]string, 0, len(bs.Properties))
			for p := range bs.Properties {
				props = append(props, p)
			}
			sort.Strings(props)
			for _, p := range props {
				ref := bs.Properties[p]
				_, required := reqSet[p]
				typ := r.goFieldType(ref, required, "models.")
				tag := jsonTag(p, required, ref.Nullable)
				fmt.Fprintf(sb, "\t%s %s %s\n", fieldName(p), typ, tag)
			}
		}
	}

	// Embedded RequestScope.
	if hasScope {
		sb.WriteString("\tmodels.RequestScope\n")
	}

	sb.WriteString("}\n\n")
}

// pathParamGoType picks the Go type for a path param. Most are string; a few
// (githubOwnerId, etc.) are int64 even in path position.
func pathParamGoType(p Parameter) string {
	switch p.Schema.Type {
	case "integer":
		if p.Schema.Format == "int64" {
			return "int64"
		}
		return "int"
	default:
		return "string"
	}
}

// queryParamGoType picks the Go type for a query param. Arrays become slices;
// scalars use their underlying type. $refs to enum-typed components become the
// typed enum. prefix is the package qualifier for model refs ("models." outside
// the models package, "" inside).
func (r *modelRegistry) queryParamGoType(p Parameter, prefix string) string {
	return r.goType(p.Schema, prefix)
}

// emitMethod writes the typed method body. It explicitly:
//   1. Interpolates path params (url.PathEscape, format int64s).
//   2. Builds url.Values from DefaultParams + url-tagged fields +
//      embedded RequestScope.
//   3. Marshals the body from json-tagged fields.
//   4. Calls c.do.
//   5. Decodes the response into a typed pointer (when an output schema is
//      defined; otherwise returns ([]byte, error)).
func emitMethod(sb *strings.Builder, ep Endpoint, r *modelRegistry) {
	outputType := ""
	if ep.OutputSchema != "" {
		if _, ok := r.schemas[ep.OutputSchema]; ok {
			outputType = "models." + ep.OutputSchema
		}
	}

	writeDocComment(sb, fmt.Sprintf("%s - %s", ep.FuncName, ep.Summary))
	writeDocComment(sb, fmt.Sprintf("%s %s", ep.Method, ep.Path))

	if outputType != "" {
		fmt.Fprintf(sb, "func (c *Client) %s(ctx context.Context, in %s) (*%s, error) {\n", ep.FuncName, inputStructName(ep), outputType)
	} else {
		fmt.Fprintf(sb, "func (c *Client) %s(ctx context.Context, in %s) ([]byte, error) {\n", ep.FuncName, inputStructName(ep))
	}

	// Path with PathEscape per path-param.
	fmt.Fprintf(sb, "\tpath := %q\n", ep.Path)
	pathNames := extractPathParamNames(ep.Path)
	pathLookup := map[string]Parameter{}
	for _, p := range ep.Parameters {
		if p.In == "path" {
			pathLookup[p.Name] = p
		}
	}
	for _, pn := range pathNames {
		p := pathLookup[pn]
		f := fieldName(pn)
		switch pathParamGoType(p) {
		case "int64":
			fmt.Fprintf(sb, "\tpath = strings.Replace(path, \"{%s}\", url.PathEscape(strconv.FormatInt(in.%s, 10)), 1)\n", pn, f)
		case "int":
			fmt.Fprintf(sb, "\tpath = strings.Replace(path, \"{%s}\", url.PathEscape(strconv.Itoa(in.%s)), 1)\n", pn, f)
		default:
			fmt.Fprintf(sb, "\tpath = strings.Replace(path, \"{%s}\", url.PathEscape(in.%s), 1)\n", pn, f)
		}
	}

	sb.WriteString("\n\tquery := url.Values{}\n\tfor k, v := range c.DefaultParams {\n\t\tquery.Set(k, v)\n\t}\n")

	// Query encoding for non-scope params.
	hasScope := false
	for _, p := range ep.Parameters {
		if p.In != "query" {
			continue
		}
		if _, scope := requestScopeParams[p.Name]; scope {
			hasScope = true
			continue
		}
		emitQueryEncode(sb, p, r)
	}
	if hasScope {
		sb.WriteString("\tin.RequestScope.AddTo(query)\n")
	}

	sb.WriteString("\n\tfullURL := fmt.Sprintf(\"%s%s\", c.BaseURL, path)\n\tif len(query) > 0 {\n\t\tfullURL += \"?\" + query.Encode()\n\t}\n\n")

	// Body marshal.
	if ep.HasBody && ep.BodySchema != "" {
		emitBodyMarshal(sb, ep, r)
		fmt.Fprintf(sb, "\tdata, err := c.do(ctx, %q, fullURL, bytes.NewReader(bodyBytes))\n", ep.Method)
	} else if ep.HasBody {
		// Body declared but no schema (rare). Pass empty body.
		fmt.Fprintf(sb, "\tdata, err := c.do(ctx, %q, fullURL, nil)\n", ep.Method)
	} else {
		fmt.Fprintf(sb, "\tdata, err := c.do(ctx, %q, fullURL, nil)\n", ep.Method)
	}

	if outputType != "" {
		sb.WriteString("\tif err != nil {\n\t\treturn nil, err\n\t}\n")
		fmt.Fprintf(sb, "\tvar out %s\n", outputType)
		sb.WriteString("\tif err := json.Unmarshal(data, &out); err != nil {\n\t\treturn nil, fmt.Errorf(\"decode response: %w\", err)\n\t}\n")
		sb.WriteString("\treturn &out, nil\n")
	} else {
		sb.WriteString("\treturn data, err\n")
	}

	sb.WriteString("}\n\n")
}

// emitQueryEncode writes the code that copies one non-scope query param from
// the input struct into url.Values, handling slices and typed scalars. Slice
// fields are stored as []T (no pointer) so iterate directly; scalar fields are
// stored as *T (optional) so dereference behind a nil-check.
func emitQueryEncode(sb *strings.Builder, p Parameter, r *modelRegistry) {
	f := fieldName(p.Name)
	typ := r.queryParamGoType(p, "models.")

	switch {
	case strings.HasPrefix(typ, "[]"):
		inner := strings.TrimPrefix(typ, "[]")
		switch inner {
		case "int64":
			fmt.Fprintf(sb, "\tfor _, v := range in.%s {\n\t\tquery.Add(%q, strconv.FormatInt(v, 10))\n\t}\n", f, p.Name)
		case "int", "int32":
			fmt.Fprintf(sb, "\tfor _, v := range in.%s {\n\t\tquery.Add(%q, strconv.Itoa(int(v)))\n\t}\n", f, p.Name)
		case "bool":
			fmt.Fprintf(sb, "\tfor _, v := range in.%s {\n\t\tquery.Add(%q, strconv.FormatBool(v))\n\t}\n", f, p.Name)
		case "float64":
			fmt.Fprintf(sb, "\tfor _, v := range in.%s {\n\t\tquery.Add(%q, strconv.FormatFloat(v, 'f', -1, 64))\n\t}\n", f, p.Name)
		default:
			// string and typed-string enums
			fmt.Fprintf(sb, "\tfor _, v := range in.%s {\n\t\tquery.Add(%q, string(v))\n\t}\n", f, p.Name)
		}
	case typ == "int64":
		fmt.Fprintf(sb, "\tif in.%s != nil {\n\t\tquery.Set(%q, strconv.FormatInt(*in.%s, 10))\n\t}\n", f, p.Name, f)
	case typ == "int" || typ == "int32":
		fmt.Fprintf(sb, "\tif in.%s != nil {\n\t\tquery.Set(%q, strconv.Itoa(int(*in.%s)))\n\t}\n", f, p.Name, f)
	case typ == "bool":
		fmt.Fprintf(sb, "\tif in.%s != nil {\n\t\tquery.Set(%q, strconv.FormatBool(*in.%s))\n\t}\n", f, p.Name, f)
	case typ == "float64":
		fmt.Fprintf(sb, "\tif in.%s != nil {\n\t\tquery.Set(%q, strconv.FormatFloat(*in.%s, 'f', -1, 64))\n\t}\n", f, p.Name, f)
	default:
		// string (incl. typed-string enums)
		fmt.Fprintf(sb, "\tif in.%s != nil {\n\t\tquery.Set(%q, string(*in.%s))\n\t}\n", f, p.Name, f)
	}
}

// emitBodyMarshal writes code that constructs and marshals the request body
// from the json-tagged fields of the input struct. We build an anonymous
// struct literal rather than re-using the input struct, so path/url tagged
// fields don't leak into the JSON.
func emitBodyMarshal(sb *strings.Builder, ep Endpoint, r *modelRegistry) {
	bs, ok := r.schemas[ep.BodySchema]
	if !ok {
		sb.WriteString("\tbodyBytes := []byte(nil)\n")
		return
	}
	reqSet := map[string]struct{}{}
	for _, name := range bs.Required {
		reqSet[name] = struct{}{}
	}
	props := make([]string, 0, len(bs.Properties))
	for p := range bs.Properties {
		props = append(props, p)
	}
	sort.Strings(props)

	sb.WriteString("\tbodyBytes, err := json.Marshal(struct {\n")
	for _, p := range props {
		ref := bs.Properties[p]
		_, required := reqSet[p]
		typ := r.goFieldType(ref, required, "models.")
		tag := jsonTag(p, required, ref.Nullable)
		fmt.Fprintf(sb, "\t\t%s %s %s\n", fieldName(p), typ, tag)
	}
	sb.WriteString("\t}{\n")
	for _, p := range props {
		fmt.Fprintf(sb, "\t\t%s: in.%s,\n", fieldName(p), fieldName(p))
	}
	sb.WriteString("\t})\n")
	sb.WriteString("\tif err != nil {\n\t\treturn nil, fmt.Errorf(\"marshal body: %w\", err)\n\t}\n")
}
