package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
	"github.com/nullify-platform/cli/internal/apierror"
)

// Errors that FixResult.Failure holds when a fix did not deliver its result.
var (
	ErrAutofixFailed       = errors.New("autofix failed")
	ErrAutofixStillRunning = errors.New("autofix is still running")
	ErrNoPullRequest       = errors.New("autofix finished without opening a new pull request")
	ErrAutofixDiff         = errors.New("get autofix diff")
)

// ErrInvalidTimeout is returned before the API is called.
var ErrInvalidTimeout = errors.New("timeout must be greater than zero")

// DefaultFixTimeout is longer than the 45 minutes that the server allows one
// autofix run, so that a healthy run ends before the wait does.
const DefaultFixTimeout = 50 * time.Minute

// autoFixStateCached is the one terminal fix-generation state that carries no
// pull request. When waiting on pull-request creation, a poll must not stop here
// even though the server reports terminal=true.
const autoFixStateCached = "cached"

const autoFixStateFailedIteration = "failed_iteration"

// autofixSuccessStates are the terminal states in which the run produced a fix.
// Every other terminal state, known or not, is a failure.
var autofixSuccessStates = []string{autoFixStateCached, "pending_review", "pr_merged"}

var autofixPollInterval = 3 * time.Second

// AutofixStatus is the part of the autofix status payload that polling reads.
type AutofixStatus struct {
	State       string `json:"state"`
	Terminal    bool   `json:"terminal"`
	Explanation string `json:"autofixVerdictExplanation"`
	// PullRequests is the history of autofix pull requests on the finding, most
	// recent first. The pullRequestUrl field is not read, because it can name a
	// pull request of an earlier run.
	PullRequests []AutofixPullRequest `json:"pullRequests"`
}

// AutofixPullRequest is one entry in the pull-request history of a finding.
type AutofixPullRequest struct {
	URL    string `json:"url"`
	Status string `json:"status"`
}

// FixResult is the outcome of Fix.
type FixResult struct {
	// State is the last autofix state that the run reported.
	State string
	// RunID identifies the run. It is empty when the server does not report one.
	RunID string
	// CheckWith is the command that reports a run that continues on the server. It
	// is set when the wait ended before the run did.
	CheckWith string
	// Diff is the proposed change. It is empty for a type with no diff route.
	Diff json.RawMessage
	// PullRequest is set when the run opened a pull request, or when its latest
	// iteration failed and left a pull request open.
	PullRequest *PullRequestStatus
	// Failure is why the run did not deliver its result. It is nil on success.
	Failure error
}

// PullRequestStatus is the pull-request phase of an autofix run.
type PullRequestStatus struct {
	State string `json:"state,omitempty"`
	URL   string `json:"url,omitempty"`
}

// FixStart is the answer to a request that starts an autofix run.
type FixStart struct {
	State string `json:"autoFixState"`
	RunID string `json:"runId"`
}

// FixOptions control how long Fix waits and for what.
type FixOptions struct {
	// WaitForPR also waits for a pull request that the run opens.
	WaitForPR bool
	// Timeout is the longest that Fix waits for the run.
	Timeout time.Duration
}

// StartFix starts the autofix agent for a finding and returns at once. The run
// continues on the server, and the fix-status verb reports it.
func StartFix(ctx context.Context, c *api.Client, typeName, findingID string) (FixStart, error) {
	t, err := fixType(typeName, findingID)
	if err != nil {
		return FixStart{}, err
	}
	return startFix(ctx, c, t, findingID)
}

// Fix starts the autofix agent for a finding, waits for it to end and returns
// the diff. The fix run opens any pull request itself, so WaitForPR only waits
// for a pull request that was not on the finding before the run. The returned
// error is a failure to call the API; FixResult.Failure is a run that failed.
// When the run started before the failure, the result still holds what is known
// about it, and CheckWith is set.
func Fix(ctx context.Context, c *api.Client, typeName, findingID string, opts FixOptions) (FixResult, error) {
	t, err := fixType(typeName, findingID)
	if err != nil {
		return FixResult{}, err
	}
	if opts.Timeout <= 0 {
		return FixResult{}, fmt.Errorf("%w: %s", ErrInvalidTimeout, opts.Timeout)
	}

	var earlier []string
	if opts.WaitForPR {
		before, err := readAutofixStatus(ctx, c, t, findingID)
		if err != nil {
			return FixResult{}, err
		}
		for _, pr := range before.PullRequests {
			earlier = append(earlier, pr.URL)
		}
	}

	start, err := startFix(ctx, c, t, findingID)
	if err != nil {
		return FixResult{}, err
	}
	result := FixResult{State: start.State, RunID: start.RunID}
	deadline := time.Now().Add(opts.Timeout)
	check := fmt.Sprintf("nullify findings fix-status %s --type %s", findingID, typeName)
	stillRunning := fmt.Errorf("%w after %s; check it with: %s", ErrAutofixStillRunning, opts.Timeout, check)

	status, err := pollAutofix(ctx, c, t, findingID, false, earlier, deadline)
	if status.State != "" {
		result.State = status.State
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result.CheckWith = check
		result.Failure = stillRunning
		return result, nil
	}
	if err != nil {
		result.CheckWith = check
		return result, fmt.Errorf("the run started but its status cannot be read; check it with: %s: %w", check, err)
	}

	if !status.succeeded() {
		result.PullRequest = status.openPullRequestOfFailedIteration()
		result.Failure = status.failure()
		return result, nil
	}

	var diffErr error
	if t.AutofixDiff != nil {
		result.Diff, err = t.AutofixDiff(ctx, c, findingID, nil)
		if err != nil {
			diffErr = fmt.Errorf("%w: %w", ErrAutofixDiff, err)
		}
	}

	if !opts.WaitForPR {
		result.Failure = diffErr
		return result, nil
	}

	status, err = pollAutofix(ctx, c, t, findingID, true, earlier, deadline)
	if status.State != "" {
		result.State = status.State
	}
	if errors.Is(err, context.DeadlineExceeded) {
		result.CheckWith = check
		result.Failure = errors.Join(diffErr, stillRunning)
		return result, nil
	}
	if err != nil {
		result.CheckWith = check
		return result, fmt.Errorf("the run started but its status cannot be read; check it with: %s: %w", check, err)
	}

	if pr := status.newPullRequest(earlier); pr != nil {
		result.PullRequest = &PullRequestStatus{State: pr.Status, URL: pr.URL}
	}
	switch {
	case !status.succeeded():
		if result.PullRequest == nil {
			result.PullRequest = status.openPullRequestOfFailedIteration()
		}
		result.Failure = errors.Join(diffErr, status.failure())
	case result.PullRequest == nil:
		result.Failure = errors.Join(diffErr, fmt.Errorf("%w: state %s", ErrNoPullRequest, status.State))
	default:
		result.Failure = diffErr
	}
	return result, nil
}

func fixType(typeName, findingID string) (Type, error) {
	t, err := Lookup(typeName)
	if err != nil {
		return Type{}, err
	}
	if t.AutofixFix == nil {
		return Type{}, fmt.Errorf("autofix of type %q: %w", typeName, ErrUnsupported)
	}
	if findingID == "" {
		return Type{}, ErrFindingIDRequired
	}
	return t, nil
}

func startFix(ctx context.Context, c *api.Client, t Type, findingID string) (FixStart, error) {
	data, err := t.AutofixFix(ctx, c, findingID, nil)
	if err != nil {
		return FixStart{}, fmt.Errorf("trigger autofix: %w", err)
	}

	var start FixStart
	if err := json.Unmarshal(data, &start); err != nil {
		return FixStart{}, fmt.Errorf("decode autofix start: %w", err)
	}
	return start, nil
}

func (s AutofixStatus) succeeded() bool {
	return slices.Contains(autofixSuccessStates, s.State)
}

func (s AutofixStatus) failure() error {
	if s.Explanation != "" {
		return fmt.Errorf("%w: state %s: %s", ErrAutofixFailed, s.State, s.Explanation)
	}
	return fmt.Errorf("%w: state %s", ErrAutofixFailed, s.State)
}

// newPullRequest returns the most recent pull request that is not in earlier.
func (s AutofixStatus) newPullRequest(earlier []string) *AutofixPullRequest {
	for _, pr := range s.PullRequests {
		if pr.URL != "" && !slices.Contains(earlier, pr.URL) {
			return &pr
		}
	}
	return nil
}

// openPullRequestOfFailedIteration returns the open pull request when the latest
// iteration failed. The pull request stays open with its earlier commits.
func (s AutofixStatus) openPullRequestOfFailedIteration() *PullRequestStatus {
	if s.State != autoFixStateFailedIteration {
		return nil
	}
	for _, pr := range s.PullRequests {
		if pr.Status == string(models.ModelsPullRequestStateOpen) {
			return &PullRequestStatus{State: pr.Status, URL: pr.URL}
		}
	}
	return nil
}

// autofixPhaseDone reports whether the watched autofix phase has ended, with the
// server-computed terminal flag as the authority.
func autofixPhaseDone(st AutofixStatus, watchPR bool, earlier []string) bool {
	if watchPR {
		return st.newPullRequest(earlier) != nil || (st.Terminal && st.State != autoFixStateCached)
	}
	return st.Terminal
}

func readAutofixStatus(ctx context.Context, c *api.Client, t Type, findingID string) (AutofixStatus, error) {
	data, err := t.AutofixStatus(ctx, c, findingID, nil)
	if err != nil {
		return AutofixStatus{}, fmt.Errorf("poll autofix status: %w", err)
	}

	var wrapper struct {
		Status AutofixStatus `json:"status"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return AutofixStatus{}, fmt.Errorf("decode autofix status: %w", err)
	}
	return wrapper.Status, nil
}

// transientPollError reports whether a later poll can succeed. A long wait must
// not fail a healthy run because of one bad response.
func transientPollError(err error) bool {
	var apiErr *apierror.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= http.StatusInternalServerError || apiErr.StatusCode == http.StatusTooManyRequests
	}
	return true
}

// pollAutofix polls the autofix status route until the watched phase ends or the
// deadline passes. On the deadline it returns the last status it read and
// context.DeadlineExceeded.
func pollAutofix(ctx context.Context, c *api.Client, t Type, findingID string, watchPR bool, earlier []string, deadline time.Time) (AutofixStatus, error) {
	var last AutofixStatus
	for {
		status, err := readAutofixStatus(ctx, c, t, findingID)
		switch {
		case err == nil:
			last = status
			if autofixPhaseDone(status, watchPR, earlier) {
				return status, nil
			}
		case ctx.Err() != nil || !transientPollError(err):
			return last, err
		}

		if time.Now().After(deadline) {
			return last, context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(autofixPollInterval):
		}
	}
}
