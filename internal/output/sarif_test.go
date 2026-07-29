package output

import (
	"encoding/json"
	"testing"
)

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "error"},
		{"CRITICAL", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
		{"informational", "note"},
		{"", "warning"},
		{"weird", "warning"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			if got := severityToSARIFLevel(tt.severity); got != tt.want {
				t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestBuildSARIF(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		wantErr     bool
		wantResults int
		wantRules   []string
		// assert checks the produced log for shape-specific expectations.
		assert func(t *testing.T, log sarifLog)
	}{
		{
			name:    "unrecognized shape errors",
			data:    `"just a string"`,
			wantErr: true,
		},
		{
			name:        "empty findings object",
			data:        `{"findings": [], "total": 0}`,
			wantResults: 0,
		},
		{
			name:        "empty top-level array",
			data:        `[]`,
			wantResults: 0,
		},
		{
			name: "findings object with locations and rules",
			data: `{"findings":[
				{"severity":"critical","title":"SQLi","ruleId":"sql-injection","filePath":"src/db.go","startLine":42},
				{"severity":"high","title":"XSS","ruleId":"xss","file":"web.js","line":7}
			],"total":2}`,
			wantResults: 2,
			wantRules:   []string{"sql-injection", "xss"},
			assert: func(t *testing.T, log sarifLog) {
				res := log.Runs[0].Results
				if res[0].Level != "error" {
					t.Errorf("result[0] level = %q, want error", res[0].Level)
				}
				if len(res[0].Locations) != 1 {
					t.Fatalf("result[0] expected 1 location, got %d", len(res[0].Locations))
				}
				loc := res[0].Locations[0].PhysicalLocation
				if loc.ArtifactLocation.URI != "src/db.go" {
					t.Errorf("uri = %q, want src/db.go", loc.ArtifactLocation.URI)
				}
				if loc.Region == nil || loc.Region.StartLine != 42 {
					t.Errorf("region = %+v, want startLine 42", loc.Region)
				}
			},
		},
		{
			name:        "top-level array shape still works",
			data:        `[{"severity":"medium","title":"Weak crypto","id":"crypto-1"}]`,
			wantResults: 1,
			wantRules:   []string{"crypto-1"},
			assert: func(t *testing.T, log sarifLog) {
				if log.Runs[0].Results[0].Level != "warning" {
					t.Errorf("level = %q, want warning", log.Runs[0].Results[0].Level)
				}
			},
		},
		{
			name:        "dast finding uses url for location",
			data:        `{"findings":[{"severity":"high","title":"Open redirect","rule_id":"redirect","url":"https://x.test/a"}],"total":1}`,
			wantResults: 1,
			wantRules:   []string{"redirect"},
			assert: func(t *testing.T, log sarifLog) {
				loc := log.Runs[0].Results[0].Locations
				if len(loc) != 1 {
					t.Fatalf("expected 1 location, got %d", len(loc))
				}
				if loc[0].PhysicalLocation.ArtifactLocation.URI != "https://x.test/a" {
					t.Errorf("uri = %q, want url", loc[0].PhysicalLocation.ArtifactLocation.URI)
				}
				if loc[0].PhysicalLocation.Region != nil {
					t.Errorf("expected no region for url-only finding, got %+v", loc[0].PhysicalLocation.Region)
				}
			},
		},
		{
			name:        "missing fields do not panic and omit location",
			data:        `{"findings":[{}],"total":1}`,
			wantResults: 1,
			wantRules:   nil,
			assert: func(t *testing.T, log sarifLog) {
				r := log.Runs[0].Results[0]
				if r.Message.Text != "Security finding" {
					t.Errorf("message = %q, want default", r.Message.Text)
				}
				if len(r.Locations) != 0 {
					t.Errorf("expected no locations, got %d", len(r.Locations))
				}
			},
		},
		{
			name:        "duplicate ruleIds deduped in rules",
			data:        `{"findings":[{"ruleId":"r1","title":"a"},{"ruleId":"r1","title":"b"}],"total":2}`,
			wantResults: 2,
			wantRules:   []string{"r1"},
		},
		{
			name:        "wrapped per-type results",
			data:        `[{"type":"sast","data":[{"severity":"low","title":"Lint","ruleId":"lint-1","path":"a.go","lineNumber":3}]}]`,
			wantResults: 1,
			wantRules:   []string{"lint-1"},
			assert: func(t *testing.T, log sarifLog) {
				loc := log.Runs[0].Results[0].Locations
				if len(loc) != 1 || loc[0].PhysicalLocation.Region == nil || loc[0].PhysicalLocation.Region.StartLine != 3 {
					t.Errorf("expected location with startLine 3, got %+v", loc)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log, err := buildSARIF([]byte(tt.data))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if log.Version != "2.1.0" {
				t.Errorf("version = %q, want 2.1.0", log.Version)
			}
			if len(log.Runs) != 1 {
				t.Fatalf("expected 1 run, got %d", len(log.Runs))
			}

			run := log.Runs[0]
			if len(run.Results) != tt.wantResults {
				t.Errorf("results = %d, want %d", len(run.Results), tt.wantResults)
			}

			gotRules := make([]string, 0, len(run.Tool.Driver.Rules))
			for _, r := range run.Tool.Driver.Rules {
				gotRules = append(gotRules, r.ID)
			}
			if len(gotRules) != len(tt.wantRules) {
				t.Fatalf("rules = %v, want %v", gotRules, tt.wantRules)
			}
			for i, id := range tt.wantRules {
				if gotRules[i] != id {
					t.Errorf("rules[%d] = %q, want %q", i, gotRules[i], id)
				}
			}

			if tt.assert != nil {
				tt.assert(t, log)
			}
		})
	}
}

func TestSARIFBytesValidJSON(t *testing.T) {
	data := `{"findings":[{"severity":"high","title":"x","ruleId":"r","filePath":"f.go","startLine":1}],"total":1}`
	out, err := SARIFBytes([]byte(data))
	if err != nil {
		t.Fatalf("SARIFBytes error: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty SARIF output")
	}
	var doc sarifLog
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("SARIFBytes produced invalid JSON: %v", err)
	}
	if doc.Version != "2.1.0" || len(doc.Runs) != 1 {
		t.Errorf("unexpected SARIF doc: %+v", doc)
	}
}
