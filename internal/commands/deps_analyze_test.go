package commands

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/ci"
	"github.com/nullify-platform/cli/internal/scan"
	"github.com/nullify-platform/cli/internal/scan/manifest"
)

func dep(name string) scan.ChangedDep {
	return scan.ChangedDep{Ecosystem: manifest.EcosystemNPM, Name: name, Version: "1.0.0", Kind: scan.KindAdded}
}

func TestCheckFailOn(t *testing.T) {
	cases := []struct {
		name     string
		failOn   string
		verdict  Verdict
		wantErr  bool
		wantExit int
	}{
		{"none_benign", "none", VerdictBenign, false, 0},
		{"none_malicious", "none", VerdictMalicious, false, 0}, // none never fails
		{"none_empty", "none", "", false, 0},
		{"default_benign", "malicious", VerdictBenign, false, 0},
		{"default_vulnerable", "malicious", VerdictVulnerable, false, 0},
		{"default_suspicious", "malicious", VerdictSuspicious, false, 0},
		{"default_malicious", "malicious", VerdictMalicious, true, exitMaliciousFound},
		{"vuln_threshold_vuln", "vulnerable", VerdictVulnerable, true, exitVulnerableFound},
		{"vuln_threshold_benign", "vulnerable", VerdictBenign, false, 0},
		{"susp_threshold_susp", "suspicious", VerdictSuspicious, true, exitSuspiciousFound},
		{"susp_threshold_vuln", "suspicious", VerdictVulnerable, false, 0},
		{"empty_verdict_never_fails", "vulnerable", "", false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			worst := classifyVerdict(c.verdict, dep("x"))
			err := checkFailOn(c.failOn, worst)
			if (err != nil) != c.wantErr {
				t.Fatalf("checkFailOn(%q, %q) err = %v, wantErr %v", c.failOn, c.verdict, err, c.wantErr)
			}
			if c.wantErr && ExitCodeFromError(err) != c.wantExit {
				t.Errorf("exit code = %d, want %d", ExitCodeFromError(err), c.wantExit)
			}
		})
	}
}

func TestClassifyVerdict_UnknownFailsClosed(t *testing.T) {
	worst := classifyVerdict(Verdict("brand_new_label"), dep("evil"))
	if worst.rank != 4 {
		t.Fatalf("unknown verdict rank = %d, want 4 (malicious)", worst.rank)
	}
	// Crosses every threshold except none.
	if err := checkFailOn("malicious", worst); err == nil {
		t.Error("unknown verdict should fail --fail-on=malicious")
	}
	if err := checkFailOn("vulnerable", worst); err == nil {
		t.Error("unknown verdict should fail --fail-on=vulnerable")
	}
	if err := checkFailOn("none", worst); err != nil {
		t.Errorf("unknown verdict should NOT fail --fail-on=none, got %v", err)
	}
	if ExitCodeFromError(checkFailOn("malicious", worst)) != exitMaliciousFound {
		t.Error("unknown verdict should exit with malicious code")
	}
}

func TestExitCodeFromError(t *testing.T) {
	if got := ExitCodeFromError(nil); got != 0 {
		t.Errorf("nil → %d, want 0", got)
	}
	if got := ExitCodeFromError(exitError(exitMaliciousFound, "boom")); got != exitMaliciousFound {
		t.Errorf("exitErr → %d, want %d", got, exitMaliciousFound)
	}
	if got := ExitCodeFromError(context.Canceled); got != exitTransientFailure {
		t.Errorf("plain error → %d, want %d", got, exitTransientFailure)
	}
}

func TestBuildIdempotencyKey(t *testing.T) {
	t.Setenv("NULLIFY_IDEMPOTENCY_SEED", "")
	clearLocalEnv(t)
	p := ci.NewLocal()
	d := dep("lodash")

	// Default seed is provider-name scoped (stable across runs).
	got := buildIdempotencyKey("", p, d)
	want := "ci-OTHER|npm|lodash|1.0.0"
	if got != want {
		t.Errorf("default key = %q, want %q", got, want)
	}
	// Explicit seed wins.
	if got := buildIdempotencyKey("myseed", p, d); got != "myseed|npm|lodash|1.0.0" {
		t.Errorf("explicit seed key = %q", got)
	}
}

func clearLocalEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BITBUCKET_BUILD_NUMBER", "JENKINS_URL", "TF_BUILD", "BUILD_ID", "PROJECT_ID", "CODEBUILD_BUILD_ID"} {
		t.Setenv(k, "")
	}
}

func TestRenderResults_AlignmentWithFailure(t *testing.T) {
	// A middle failure must not shift verdicts onto the wrong dep — the
	// JSON path encodes one entry per dep with its own outcome.
	analyzed := []analyzedDep{
		{Dep: dep("a"), Resp: &scpmAnalyzeResponse{JobID: "j1", Verdict: VerdictBenign}},
		{Dep: dep("b"), Err: "scpm 500"},
		{Dep: dep("c"), Resp: &scpmAnalyzeResponse{JobID: "j3", Verdict: VerdictMalicious}},
	}
	// text + json render without panicking / mismatching lengths.
	if err := renderResults("text", analyzed); err != nil {
		t.Fatalf("text render: %v", err)
	}
	if err := renderResults("json", analyzed); err != nil {
		t.Fatalf("json render: %v", err)
	}
	if err := renderResults("bogus", analyzed); err == nil {
		t.Error("expected error for unknown format")
	}
}

func TestIsTerminal(t *testing.T) {
	cases := []struct {
		resp scpmAnalyzeResponse
		want bool
	}{
		{scpmAnalyzeResponse{CacheHit: true}, true},
		{scpmAnalyzeResponse{Verdict: VerdictBenign}, true},
		{scpmAnalyzeResponse{Status: "completed"}, true},
		{scpmAnalyzeResponse{Status: "FAILED"}, true},
		{scpmAnalyzeResponse{Status: "queued"}, false},
		{scpmAnalyzeResponse{Status: "running"}, false},
		{scpmAnalyzeResponse{}, false},
	}
	for _, c := range cases {
		if got := isTerminal(&c.resp); got != c.want {
			t.Errorf("isTerminal(%+v) = %v, want %v", c.resp, got, c.want)
		}
	}
}

func TestAnalyzeDep_CacheHitNoWait(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jobId":"j1","status":"completed","cacheHit":true,"verdict":"benign"}`))
	}))
	defer srv.Close()

	client := &api.Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	resp, err := analyzeDep(context.Background(), client, ci.NewLocal(), scpmAnalyzeRequest{Name: "x"}, depsAnalyzeOpts{})
	if err != nil {
		t.Fatalf("analyzeDep: %v", err)
	}
	if resp.Verdict != VerdictBenign {
		t.Errorf("verdict = %q, want benign", resp.Verdict)
	}
}

func TestAnalyzeDep_WaitPollsUntilTerminal(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			_, _ = w.Write([]byte(`{"jobId":"j1","status":"running"}`))
			return
		}
		_, _ = w.Write([]byte(`{"jobId":"j1","status":"completed","verdict":"confirmed_malicious"}`))
	}))
	defer srv.Close()

	client := &api.Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	opts := depsAnalyzeOpts{Wait: true, WaitInterval: time.Millisecond, WaitTimeout: 5 * time.Second}
	resp, err := analyzeDep(context.Background(), client, ci.NewLocal(), scpmAnalyzeRequest{Name: "x"}, opts)
	if err != nil {
		t.Fatalf("analyzeDep: %v", err)
	}
	if resp.Verdict != VerdictMalicious {
		t.Errorf("verdict = %q, want confirmed_malicious", resp.Verdict)
	}
	if calls.Load() < 3 {
		t.Errorf("expected >=3 polls, got %d", calls.Load())
	}
}

func TestAnalyzeDep_WaitTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jobId":"j1","status":"running"}`))
	}))
	defer srv.Close()

	client := &api.Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	opts := depsAnalyzeOpts{Wait: true, WaitInterval: time.Millisecond, WaitTimeout: 20 * time.Millisecond}
	if _, err := analyzeDep(context.Background(), client, ci.NewLocal(), scpmAnalyzeRequest{Name: "x"}, opts); err == nil {
		t.Fatal("expected wait-timeout error")
	}
}

func TestPostSCPMAnalyze_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	client := &api.Client{BaseURL: srv.URL, HTTPClient: srv.Client()}
	if _, err := postSCPMAnalyze(context.Background(), client, ci.NewLocal(), scpmAnalyzeRequest{Name: "x"}); err == nil {
		t.Fatal("expected error on 500")
	}
}
