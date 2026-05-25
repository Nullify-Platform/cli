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

// Stable exit-code table so CI operators can gate merges. These mirror
// the global codes in cmd/cli/cmd/exitcodes.go where they overlap (1 =
// transient/retry, 2 = invalid invocation) and add the deps-specific
// severity codes 10/20/30. They live here rather than in the cmd package
// because cmd imports commands — referencing the cmd constants would be
// an import cycle. main.go maps these onto os.Exit via ExitCodeFromError.
const (
	exitVulnerableFound   = 10
	exitSuspiciousFound   = 20
	exitMaliciousFound    = 30
	exitInvalidInvocation = 2
	exitTransientFailure  = 1
)

// Verdict is a dependency malware-analysis verdict as returned by
// vuln-database (passed through scpm). The recognised set is below; any
// other non-empty verdict is treated as unknown and fails closed (see
// classifyVerdict) so a server-side rename can't silently bypass the gate.
type Verdict string

const (
	VerdictBenign     Verdict = "benign"
	VerdictVulnerable Verdict = "vulnerable"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "confirmed_malicious"
)

// Default polling cadence/cap for --wait. Analysis is asynchronous, so
// without --wait the first response usually carries an empty verdict.
const (
	defaultWaitTimeout  = 5 * time.Minute
	defaultWaitInterval = 5 * time.Second
)

// terminalStatuses are the job statuses we treat as "done" when polling.
// The exact strings originate in vuln-database; this set is intentionally
// broad so an unanticipated terminal label still ends the poll rather than
// spinning to the --wait timeout. A populated verdict or a cache hit is
// also treated as terminal regardless of status.
var terminalStatuses = map[string]bool{
	"completed": true, "complete": true,
	"succeeded": true, "success": true,
	"failed": true, "failure": true,
	"error": true, "cancelled": true, "canceled": true,
}

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
		baseRef         string
		headRef         string
		repoPath        string
		wait            bool
		waitTimeout     time.Duration
		waitInterval    time.Duration
		failOn          string
		outputFormat    string
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

Analysis is asynchronous: by default each dep is enqueued and the command
returns immediately with whatever verdict is already cached. Pass --wait
to block (per --wait-timeout) until every job reaches a terminal verdict.

Exit codes:
  0  no concerning findings (or --fail-on=none)
  10 vulnerable dependency detected
  20 suspicious malware signal
  30 confirmed (or unrecognised) malicious verdict
  2  invalid invocation
  1  transient failure / incomplete analysis (retry)
`,
		// A verdict-based failure is a legitimate gate result, not a
		// usage error — don't dump cobra usage text on it.
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			return runDepsAnalyze(ctx, getClient(), depsAnalyzeOpts{
				BaseRef:         baseRef,
				HeadRef:         headRef,
				RepoPath:        repoPath,
				Wait:            wait,
				WaitTimeout:     waitTimeout,
				WaitInterval:    waitInterval,
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
	analyzeCmd.Flags().DurationVar(&waitTimeout, "wait-timeout", defaultWaitTimeout, "With --wait, give up polling a job after this long")
	analyzeCmd.Flags().DurationVar(&waitInterval, "wait-interval", defaultWaitInterval, "With --wait, delay between poll attempts")
	analyzeCmd.Flags().StringVar(&failOn, "fail-on", "malicious", "Exit non-zero when any finding of this severity or worse: vulnerable|suspicious|malicious|none")
	analyzeCmd.Flags().StringVar(&outputFormat, "format", "text", "Output format: text|json")
	analyzeCmd.Flags().StringVar(&idempotencySeed, "idempotency-seed", "", "Prefix for the scpm idempotency key; default is the CI provider name")
	depsCmd.AddCommand(analyzeCmd)
}

type depsAnalyzeOpts struct {
	BaseRef         string
	HeadRef         string
	RepoPath        string
	Wait            bool
	WaitTimeout     time.Duration
	WaitInterval    time.Duration
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
	Ecosystem       manifest.Ecosystem `json:"ecosystem"`
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	PreviousVersion string             `json:"previousVersion,omitempty"`
	IdempotencyKey  string             `json:"idempotencyKey,omitempty"`
}

type scpmAnalyzeResponse struct {
	JobID    string  `json:"jobId"`
	Status   string  `json:"status"`
	CacheHit bool    `json:"cacheHit"`
	Verdict  Verdict `json:"verdict,omitempty"`
}

// analyzedDep pairs an actionable dependency with the outcome of its
// analyze call. One entry exists per actionable dep — including failures
// (Resp nil, Err set) — so rendering and gating never rely on two
// index-aligned slices staying in sync.
type analyzedDep struct {
	Dep  scan.ChangedDep      `json:"dep"`
	Resp *scpmAnalyzeResponse `json:"resp,omitempty"`
	Err  string               `json:"error,omitempty"`
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
		base, err = provider.BaseRef(ctx, opts.RepoPath)
		if err != nil {
			return exitError(exitInvalidInvocation, "resolve base ref: %v", err)
		}
	}
	head := opts.HeadRef
	if head == "" {
		head, err = provider.HeadRef(ctx, opts.RepoPath)
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

	// Only added and bumped deps have a new version worth analysing.
	actionable := make([]scan.ChangedDep, 0, len(changed))
	for _, d := range changed {
		if d.Kind == scan.KindAdded || d.Kind == scan.KindBumped {
			actionable = append(actionable, d)
		}
	}
	fmt.Fprintf(os.Stderr, "nullify deps analyze: %d changed, %d actionable\n", len(changed), len(actionable))

	analyzed := make([]analyzedDep, 0, len(actionable))
	worst := gateOutcome{}
	errCount := 0
	for _, d := range actionable {
		req := scpmAnalyzeRequest{
			Ecosystem:       d.Ecosystem,
			Name:            d.Name,
			Version:         d.Version,
			PreviousVersion: d.PreviousVersion,
			IdempotencyKey:  buildIdempotencyKey(opts.IdempotencySeed, provider, d),
		}
		resp, err := analyzeDep(ctx, client, provider, req, opts)
		if err != nil {
			// A single failed/incomplete analysis shouldn't be silently
			// greenlit — record it and fail transiently at the end unless
			// a worse verdict already gates the run.
			fmt.Fprintf(os.Stderr, "  %s/%s@%s: analyze failed: %v\n", d.Ecosystem, d.Name, d.Version, err)
			analyzed = append(analyzed, analyzedDep{Dep: d, Err: err.Error()})
			errCount++
			continue
		}
		analyzed = append(analyzed, analyzedDep{Dep: d, Resp: resp})
		if o := classifyVerdict(resp.Verdict, d); o.rank > worst.rank {
			worst = o
		}
	}

	if err := renderResults(opts.OutputFormat, analyzed); err != nil {
		return exitError(exitTransientFailure, "render: %v", err)
	}

	if err := checkFailOn(opts.FailOn, worst); err != nil {
		return err
	}
	// Gate passed on observed verdicts, but if any analysis didn't
	// complete we can't certify the run — exit transiently so CI retries
	// rather than merging on incomplete data (unless the operator opted
	// out of gating entirely).
	if errCount > 0 && opts.FailOn != "none" {
		return exitError(exitTransientFailure, "%d of %d dependency analyses did not complete; re-run", errCount, len(actionable))
	}
	return nil
}

// gateOutcome is the worst result seen across analysed deps: a comparable
// rank, a human label for messaging, and the exit code to use if it ends
// up being the worst.
type gateOutcome struct {
	rank  int
	label string
	code  int
}

// classifyVerdict maps a verdict + its dependency to a gateOutcome.
// Recognised verdicts use their normal rank; a non-empty verdict the CLI
// doesn't recognise fails closed — it warns and is ranked as malicious so
// it crosses any --fail-on threshold except "none". An empty verdict (job
// still pending, no --wait) is not a verdict and contributes nothing.
func classifyVerdict(v Verdict, d scan.ChangedDep) gateOutcome {
	switch v {
	case "":
		return gateOutcome{}
	case VerdictBenign:
		return gateOutcome{rank: 1, label: string(v), code: exitVulnerableFound}
	case VerdictVulnerable:
		return gateOutcome{rank: 2, label: string(v), code: exitVulnerableFound}
	case VerdictSuspicious:
		return gateOutcome{rank: 3, label: string(v), code: exitSuspiciousFound}
	case VerdictMalicious:
		return gateOutcome{rank: 4, label: string(v), code: exitMaliciousFound}
	default:
		fmt.Fprintf(os.Stderr,
			"  WARNING: %s/%s@%s returned unrecognised verdict %q — failing closed (treating as malicious)\n",
			d.Ecosystem, d.Name, d.Version, v)
		return gateOutcome{rank: 4, label: string(v) + " (unrecognised)", code: exitMaliciousFound}
	}
}

// buildIdempotencyKey combines the caller-supplied seed (or, by default,
// the CI provider name) with the (ecosystem, name, version) tuple. The
// default seed is stable across runs of the same provider on purpose:
// re-runs and re-triggers of a flaky pipeline then coalesce onto the same
// scpm job and reuse its cached verdict rather than re-queuing analysis.
func buildIdempotencyKey(seed string, p ci.Provider, d scan.ChangedDep) string {
	if seed == "" {
		if v := os.Getenv("NULLIFY_IDEMPOTENCY_SEED"); v != "" {
			seed = v
		}
	}
	if seed == "" {
		seed = fmt.Sprintf("ci-%s", p.Platform())
	}
	return fmt.Sprintf("%s|%s|%s|%s", seed, d.Ecosystem, d.Name, d.Version)
}

// analyzeDep POSTs one analyze request and, when --wait is set, polls the
// same idempotent request until the job reaches a terminal state or the
// wait timeout elapses. Re-POSTing with the same idempotency key coalesces
// onto the existing job (idempotent within 24h) and returns its updated
// status/verdict.
func analyzeDep(ctx context.Context, client *api.Client, provider ci.Provider, req scpmAnalyzeRequest, opts depsAnalyzeOpts) (*scpmAnalyzeResponse, error) {
	resp, err := postSCPMAnalyze(ctx, client, provider, req)
	if err != nil {
		return nil, err
	}
	if !opts.Wait || isTerminal(resp) {
		return resp, nil
	}

	interval := opts.WaitInterval
	if interval <= 0 {
		interval = defaultWaitInterval
	}
	timeout := opts.WaitTimeout
	if timeout <= 0 {
		timeout = defaultWaitTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		wait := interval
		if remaining := time.Until(deadline); remaining < wait {
			wait = remaining
		}
		if wait <= 0 {
			return nil, fmt.Errorf("analysis still %q after %s wait timeout", resp.Status, timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		resp, err = postSCPMAnalyze(ctx, client, provider, req)
		if err != nil {
			return nil, err
		}
		if isTerminal(resp) {
			return resp, nil
		}
	}
}

// isTerminal reports whether an analyze response represents a finished
// job: a cache hit, a populated verdict, or a terminal status string.
func isTerminal(resp *scpmAnalyzeResponse) bool {
	if resp.CacheHit || resp.Verdict != "" {
		return true
	}
	return terminalStatuses[strings.ToLower(strings.TrimSpace(resp.Status))]
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
	defer func() { _ = resp.Body.Close() }()

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

// checkFailOn maps (--fail-on, worst-outcome) to an exit code. A
// zero-rank threshold means --fail-on=none, which never fails.
func checkFailOn(failOn string, worst gateOutcome) error {
	threshold := verdictRank(verdictThreshold(failOn))
	if threshold == 0 || worst.rank < threshold {
		return nil
	}
	return exitError(worst.code, "dependency gate failed: %s", worst.label)
}

// verdictRank maps a recognised verdict to the same comparable rank used
// by classifyVerdict, for translating the --fail-on threshold. Unknown
// values (including "") rank 0 here; unknown *response* verdicts are
// handled by classifyVerdict (fail-closed) before they reach the gate.
func verdictRank(v Verdict) int {
	switch v {
	case VerdictMalicious:
		return 4
	case VerdictSuspicious:
		return 3
	case VerdictVulnerable:
		return 2
	case VerdictBenign:
		return 1
	default:
		return 0
	}
}

func verdictThreshold(failOn string) Verdict {
	switch failOn {
	case "none":
		return "" // rank 0 — checkFailOn never crosses it
	case "vulnerable":
		return VerdictVulnerable
	case "suspicious":
		return VerdictSuspicious
	default: // "malicious" and the default
		return VerdictMalicious
	}
}

func renderResults(format string, analyzed []analyzedDep) error {
	switch format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(analyzed)
	case "text", "":
		for _, a := range analyzed {
			d := a.Dep
			prev := d.PreviousVersion
			if prev == "" {
				prev = "(new)"
			}
			if a.Resp == nil {
				fmt.Fprintf(os.Stdout, "  %s/%s  %s → %s  [error: %s]\n",
					d.Ecosystem, d.Name, prev, d.Version, a.Err)
				continue
			}
			verdict := string(a.Resp.Verdict)
			if verdict == "" {
				verdict = a.Resp.Status
			}
			fmt.Fprintf(os.Stdout, "  %s/%s  %s → %s  [%s]  job=%s\n",
				d.Ecosystem, d.Name, prev, d.Version, verdict, a.Resp.JobID)
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

// exitErr wraps an error with an exit code so the top-level handler in
// main.go can translate it to os.Exit(N). Declared locally so this
// command doesn't drag in the cli's main-pkg exit-code wiring.
type exitErr struct {
	Code int
	Msg  string
}

func (e exitErr) Error() string { return e.Msg }

func exitError(code int, format string, args ...any) error {
	return exitErr{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// ExitCodeFromError returns the exit code an exitErr wants, or
// exitTransientFailure (1) for any other non-nil error. main.go calls
// this to translate the workflow's result into a process exit code.
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
