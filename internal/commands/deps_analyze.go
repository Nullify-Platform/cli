package commands

// RegisterDepsAnalyzeCommand wires `nullify deps analyze` — a hand-written
// CI-pipeline workflow that detects changed dependencies between two
// commits and requests malware analysis for each via scpm's public API.
//
// Follows the RegisterContextPushCommand pattern (same file pkg,
// cobra-based, built on top of the generic api.Client for auth). The
// scpm calls are hand-rolled HTTP POSTs rather than generated API
// methods because scpm's OpenAPI regen happens in a separate pipeline
// — the generator will replace this file with a thinner version once
// the spec lands in the cli repo.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/ci"
	"github.com/nullify-platform/cli/internal/scan"
	"github.com/nullify-platform/cli/internal/scan/manifest"
	"github.com/spf13/cobra"
)

// ExitCodes — stable exit-code table so CI operators can gate merges.
const (
	exitNoFinding          = 0
	exitVulnerableFound    = 10
	exitSuspiciousFound    = 20
	exitMaliciousFound     = 30
	exitInvalidInvocation  = 2
	exitTransientFailure   = 1
)

// RegisterDepsAnalyzeCommand attaches `deps analyze` to the given
// parent command. api.Client is reused for auth (BaseURL + Token) —
// even though the scpm calls aren't in the generated surface yet,
// credentials and host come from the same source as every other
// nullify command.
func RegisterDepsAnalyzeCommand(parent *cobra.Command, getClient func() *api.Client) {
	var depsCmd *cobra.Command
	for _, c := range parent.Commands() {
		if c.Name() == "deps" {
			depsCmd = c
			break
		}
	}
	if depsCmd == nil {
		depsCmd = &cobra.Command{
			Use:   "deps",
			Short: "Dependency analysis commands",
		}
		parent.AddCommand(depsCmd)
	}

	var (
		baseRef        string
		headRef        string
		repoPath       string
		wait           bool
		failOn         string
		outputFormat   string
		idempotencySeed string
	)

	analyzeCmd := &cobra.Command{
		Use:   "analyze",
		Short: "Detect changed dependencies + request malware analysis",
		Long: `Analyse dependencies that changed between two commits.

Detects the current CI/CD platform, computes the dependency diff
between --base (default: CI-provided target branch) and --head (default
HEAD), and requests malware analysis for each new or bumped dep via
scpm /scpm/dependencies/analyze.

Exit codes:
  0  no concerning findings
  10 vulnerable dependency detected
  20 suspicious malware signal
  30 confirmed malicious
  2  invalid invocation
  1  transient failure (retry)
`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return runDepsAnalyze(ctx, getClient(), depsAnalyzeOpts{
				BaseRef:         baseRef,
				HeadRef:         headRef,
				RepoPath:        repoPath,
				Wait:            wait,
				FailOn:          failOn,
				OutputFormat:    outputFormat,
				IdempotencySeed: idempotencySeed,
			})
		},
	}

	analyzeCmd.Flags().StringVar(&baseRef, "base", "", "Base commit SHA or ref; defaults to the CI-provided target branch")
	analyzeCmd.Flags().StringVar(&headRef, "head", "HEAD", "Head commit SHA or ref")
	analyzeCmd.Flags().StringVar(&repoPath, "repo", ".", "Path to the git repository")
	analyzeCmd.Flags().BoolVar(&wait, "wait", false, "Block until every analysis job reaches a terminal verdict")
	analyzeCmd.Flags().StringVar(&failOn, "fail-on", "malicious", "Exit non-zero when any finding of this severity or worse: vulnerable|suspicious|malicious|none")
	analyzeCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text|json")
	analyzeCmd.Flags().StringVar(&idempotencySeed, "idempotency-seed", "", "Prefix for the scpm idempotency key; default is CI-provider+run-id")
	depsCmd.AddCommand(analyzeCmd)
}

type depsAnalyzeOpts struct {
	BaseRef         string
	HeadRef         string
	RepoPath        string
	Wait            bool
	FailOn          string
	OutputFormat    string
	IdempotencySeed string
}

// scpmAnalyzeRequest / Response mirror the shape in
// scpm/internal/endpoints/dependencies_analyze_post.go. Kept in-file
// (not a shared client package) because until the OpenAPI
// regeneration cycle completes, these are the only structs the CLI
// needs.
type scpmAnalyzeRequest struct {
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	IdempotencyKey  string `json:"idempotencyKey,omitempty"`
}

type scpmAnalyzeResponse struct {
	JobID    string `json:"jobId"`
	Status   string `json:"status"`
	CacheHit bool   `json:"cacheHit"`
	Verdict  string `json:"verdict,omitempty"`
}

func runDepsAnalyze(ctx context.Context, client *api.Client, opts depsAnalyzeOpts) error {
	if client == nil || client.BaseURL == "" {
		return exitError(exitInvalidInvocation, "no API client configured (run `nullify auth login` first)")
	}

	// Detect provider so we can auto-fill BaseRef when omitted + stamp
	// CI headers on every outbound request.
	provider, err := ci.Detect(ci.Default())
	if err != nil {
		return exitError(exitInvalidInvocation, "detect CI provider: %v", err)
	}

	base := opts.BaseRef
	if base == "" {
		base, err = provider.BaseRef(ctx)
		if err != nil {
			return exitError(exitInvalidInvocation, "resolve base ref: %v", err)
		}
	}
	head := opts.HeadRef
	if head == "" {
		head, err = provider.HeadRef(ctx)
		if err != nil {
			return exitError(exitInvalidInvocation, "resolve head ref: %v", err)
		}
	}
	// If caller passed symbolic refs, resolve to commits so the scpm
	// audit log shows the exact SHA.
	base, err = resolveCommit(ctx, opts.RepoPath, base)
	if err != nil {
		return exitError(exitInvalidInvocation, "resolve base %q: %v", base, err)
	}
	head, err = resolveCommit(ctx, opts.RepoPath, head)
	if err != nil {
		return exitError(exitInvalidInvocation, "resolve head %q: %v", head, err)
	}

	fmt.Fprintf(os.Stderr, "nullify deps analyze: %s (%s → %s)\n", provider.Platform(), short(base), short(head))

	changed, err := scan.Diff(ctx, opts.RepoPath, base, head, manifest.DefaultParsers())
	if err != nil {
		return exitError(exitTransientFailure, "compute dep diff: %v", err)
	}
	if len(changed) == 0 {
		fmt.Fprintln(os.Stderr, "nullify deps analyze: no dependency changes")
		return nil
	}

	// Only "added" and "bumped" deps have a new version worth analysing.
	actionable := make([]scan.ChangedDep, 0, len(changed))
	for _, d := range changed {
		if d.Kind == "added" || d.Kind == "bumped" {
			actionable = append(actionable, d)
		}
	}
	fmt.Fprintf(os.Stderr, "nullify deps analyze: %d changed, %d actionable\n", len(changed), len(actionable))

	results := []scpmAnalyzeResponse{}
	worstVerdict := ""
	for _, d := range actionable {
		req := scpmAnalyzeRequest{
			Ecosystem:       d.Ecosystem,
			Name:            d.Name,
			Version:         d.Version,
			PreviousVersion: d.PreviousVersion,
			IdempotencyKey:  buildIdempotencyKey(opts.IdempotencySeed, provider, d),
		}
		resp, err := postSCPMAnalyze(ctx, client, provider, req)
		if err != nil {
			// Single-dep failure shouldn't sink the whole run —
			// surface and continue. The exit code still reflects the
			// worst observed verdict across successful calls.
			fmt.Fprintf(os.Stderr, "  %s/%s@%s: analyze failed: %v\n", d.Ecosystem, d.Name, d.Version, err)
			continue
		}
		results = append(results, *resp)
		if v := verdictRank(resp.Verdict); v > verdictRank(worstVerdict) {
			worstVerdict = resp.Verdict
		}
	}

	if err := renderResults(opts.OutputFormat, actionable, results); err != nil {
		return exitError(exitTransientFailure, "render: %v", err)
	}

	return checkFailOn(opts.FailOn, worstVerdict)
}

// buildIdempotencyKey combines the caller-supplied seed (or the CI
// provider's run ID) with the (ecosystem, name, version) tuple. This
// makes a second invocation of the same CI run return cached results
// even if the CI is re-triggered (common on flaky CI).
func buildIdempotencyKey(seed string, p ci.Provider, d scan.ChangedDep) string {
	if seed == "" {
		if v := os.Getenv("NULLIFY_IDEMPOTENCY_SEED"); v != "" {
			seed = v
		}
	}
	if seed == "" {
		// Per-CI default: the run ID header the provider emits.
		seed = fmt.Sprintf("ci-%s", p.Platform())
	}
	return fmt.Sprintf("%s|%s|%s|%s", seed, d.Ecosystem, d.Name, d.Version)
}

func postSCPMAnalyze(ctx context.Context, client *api.Client, provider ci.Provider, req scpmAnalyzeRequest) (*scpmAnalyzeResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, client.BaseURL+"/scpm/dependencies/analyze", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if client.Token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+client.Token)
	}
	provider.EnrichHeader(httpReq.Header)

	httpClient := client.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("scpm %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out scpmAnalyzeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// verdictRank maps verdict strings to a comparable int so we can
// compute "worst seen" across a batch. Unknown verdicts sort below
// benign so they don't accidentally trip --fail-on=vulnerable.
func verdictRank(v string) int {
	switch v {
	case "confirmed_malicious":
		return 4
	case "suspicious":
		return 3
	case "vulnerable":
		return 2
	case "benign":
		return 1
	default:
		return 0
	}
}

// checkFailOn maps (--fail-on, worst-verdict) to an exit code.
func checkFailOn(failOn, worst string) error {
	threshold := verdictRank(verdictThreshold(failOn))
	actual := verdictRank(worst)
	if actual < threshold {
		return nil
	}
	switch worst {
	case "confirmed_malicious":
		return exitError(exitMaliciousFound, "malicious dependency detected")
	case "suspicious":
		return exitError(exitSuspiciousFound, "suspicious dependency detected")
	default:
		return exitError(exitVulnerableFound, "concerning verdict: %q", worst)
	}
}

func verdictThreshold(failOn string) string {
	switch failOn {
	case "none":
		return "" // unreachable — verdictRank("") is 0, never crossed
	case "vulnerable":
		return "vulnerable"
	case "suspicious":
		return "suspicious"
	case "malicious", "":
		return "confirmed_malicious"
	}
	return "confirmed_malicious"
}

func renderResults(format string, changed []scan.ChangedDep, results []scpmAnalyzeResponse) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"changed": changed, "results": results})
	case "text", "":
		for i, d := range changed {
			if i >= len(results) {
				break
			}
			r := results[i]
			prev := d.PreviousVersion
			if prev == "" {
				prev = "(new)"
			}
			verdict := r.Verdict
			if verdict == "" {
				verdict = r.Status
			}
			fmt.Fprintf(os.Stdout, "  %s/%s  %s → %s  [%s]  job=%s\n",
				d.Ecosystem, d.Name, prev, d.Version, verdict, r.JobID)
		}
		return nil
	default:
		return fmt.Errorf("unknown --format %q", format)
	}
}

// --- small helpers ---

func resolveCommit(ctx context.Context, repoPath, ref string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--verify", ref+"^{commit}")
	cmd.Dir = repoPath
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func short(sha string) string {
	if len(sha) > 10 {
		return sha[:10]
	}
	return sha
}

// exitErr wraps an error with an exit code so the top-level cobra
// handler can translate it to os.Exit(N). Declared locally so this
// command doesn't drag in the cli's main-pkg exit-code wiring.
type exitErr struct {
	Code int
	Msg  string
}

func (e exitErr) Error() string { return e.Msg }

func exitError(code int, format string, args ...any) error {
	return exitErr{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ExitCodeFromError returns the exit code an exitErr wants, or 1 for
// any other error. Callers use this in place of the cli's standard
// error-to-exit logic.
func ExitCodeFromError(err error) int {
	if err == nil {
		return 0
	}
	var ee exitErr
	if errors.As(err, &ee) {
		return ee.Code
	}
	return exitTransientFailure
}
