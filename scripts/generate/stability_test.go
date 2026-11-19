package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveGeneratedFiles(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		survives bool
	}{
		{name: "stale generated file", content: generatedFileMarker + "\npackage api\n", survives: false},
		{name: "hand-written file", content: "package api\n", survives: true},
		{name: "marker not on the first line", content: "package api\n\n" + generatedFileMarker + "\n", survives: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			file := filepath.Join(dir, "asset-graph.go")
			if err := os.WriteFile(file, []byte(tt.content), 0644); err != nil {
				t.Fatal(err)
			}

			if err := removeGeneratedFiles(dir); !errors.Is(err, nil) {
				t.Fatalf("removeGeneratedFiles: %v", err)
			}

			_, statErr := os.Stat(file)
			if survived := statErr == nil; survived != tt.survives {
				t.Errorf("file survived = %v, want %v", survived, tt.survives)
			}
		})
	}
}

func TestExtractEndpointsRejectsUnmappedPaths(t *testing.T) {
	tests := []struct {
		name string
		path string
		want error
	}{
		{name: "mapped service", path: "/cspm/findings", want: nil},
		{name: "cross-service feedback", path: "/findings/{findingId}/feedback", want: nil},
		{name: "explicitly excluded", path: "/public/workspace/bootstrap/start", want: nil},
		{name: "unmapped prefix", path: "/newservice/widgets", want: ErrUnmappedPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := OpenAPISpec{Paths: map[string]map[string]Operation{tt.path: {"get": {}}}}

			_, err := extractEndpoints(spec)

			if !errors.Is(err, tt.want) {
				t.Errorf("extractEndpoints(%s) error = %v, want %v", tt.path, err, tt.want)
			}
		})
	}
}

func TestAssignCobraUsesKeepsNamesStable(t *testing.T) {
	tests := []struct {
		name    string
		locked  [][3]string
		method  string
		path    string
		sibling string
		want    string
	}{
		{
			name:    "a locked name survives a new colliding sibling",
			locked:  [][3]string{{"POST /context/cloud-recon/scans", "context", "create-scans"}},
			method:  "POST",
			path:    "/context/cloud-recon/scans",
			sibling: "/context/repo-scope/scans",
			want:    "create-scans",
		},
		{
			name:    "a locked name survives a path parameter rename",
			locked:  [][3]string{{"GET /context/memories/{}/versions", "context", "get-versions"}},
			method:  "GET",
			path:    "/context/memories/{renamed}/versions",
			sibling: "/context/other/{id}/versions",
			want:    "get-versions",
		},
		{
			name:    "a name whose route left the spec is not reused",
			locked:  [][3]string{{"POST /admin/repositories/initialize", "admin", "create-initialize"}},
			method:  "POST",
			path:    "/admin/operator/external-writes/initialize",
			sibling: "/admin/unrelated",
			want:    "create-operator-external-writes-initialize",
		},
		{
			name:    "a new route with a free name takes the short name",
			method:  "POST",
			path:    "/cspm/findings/{findingId}/allowlist",
			sibling: "/cspm/findings/{findingId}/archive",
			want:    "create-allowlist-by-id",
		},
		{
			name:    "new routes that collide take qualified names",
			method:  "GET",
			path:    "/dast/pentest/scans",
			sibling: "/dast/bughunt/scans",
			want:    "list-pentest-scans",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := newCommandNames()
			for _, row := range tt.locked {
				names.useByRoute[row[0]] = row[2]
				names.service[row[0]] = row[1]
			}
			endpoints := []Endpoint{
				{Method: tt.method, Path: tt.path},
				{Method: tt.method, Path: tt.sibling},
			}

			assignCobraUses(map[string][]Endpoint{classifyService(tt.path): endpoints}, names)

			if endpoints[0].CobraUse != tt.want {
				t.Errorf("CobraUse = %q, want %q", endpoints[0].CobraUse, tt.want)
			}
		})
	}
}

func TestCommandNamesRoundTrip(t *testing.T) {
	names := newCommandNames()
	names.useByRoute["GET /asset-graph/search"] = "list-search"
	names.service["GET /asset-graph/search"] = "asset-graph"
	path := filepath.Join(t.TempDir(), "command-names.lock")

	if err := names.write(path); !errors.Is(err, nil) {
		t.Fatalf("write: %v", err)
	}
	loaded, err := loadCommandNames(path)
	if !errors.Is(err, nil) {
		t.Fatalf("load: %v", err)
	}

	if loaded.useByRoute["GET /asset-graph/search"] != "list-search" || loaded.service["GET /asset-graph/search"] != "asset-graph" {
		t.Errorf("loaded = %+v", loaded)
	}
}

// Staff-only routes reach the published bundle when they are not tagged
// Private at source. The generator keeps them out of the customer CLI,
// while their customer-facing siblings stay in.
func TestExtractEndpointsSkipsStaffOnlyOperations(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		method string
		want   bool
	}{
		{name: "operator prefix", path: "/admin/operator/tenant-capabilities", method: "get", want: false},
		{name: "run changes prefix", path: "/dast/runs/{kind}/{runId}/changes/restore", method: "post", want: false},
		{name: "staff-only credential verb", path: "/dast/credentials/{credentialId}/login-reset", method: "post", want: false},
		{name: "deprecated alias", path: "/secrets/findings/allowlist", method: "post", want: false},
		{name: "customer sibling of a staff verb", path: "/dast/credentials/{credentialId}/login-status", method: "get", want: true},
		{name: "customer batch allowlist", path: "/secrets/credentials/findings/allowlist", method: "post", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := OpenAPISpec{Paths: map[string]map[string]Operation{tt.path: {tt.method: {}}}}

			endpoints, err := extractEndpoints(spec)
			if err != nil {
				t.Fatalf("extractEndpoints(%s): %v", tt.path, err)
			}

			if got := len(endpoints) == 1; got != tt.want {
				t.Errorf("%s %s generated = %v, want %v", tt.method, tt.path, got, tt.want)
			}
		})
	}
}
