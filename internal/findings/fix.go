package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nullify-platform/cli/internal/api"
)

// autoFixStateCached is the one terminal fix-generation state that carries no
// pull request. When waiting on pull-request creation, a poll must not stop here
// even though the server reports terminal=true.
const autoFixStateCached = "cached"

var (
	autofixPollDeadline = 5 * time.Minute
	autofixPollInterval = 3 * time.Second
)

// AutofixStatus is the part of the autofix status payload that polling reads.
type AutofixStatus struct {
	State            string `json:"state"`
	Terminal         bool   `json:"terminal"`
	PullRequestState string `json:"pullRequestState"`
	PullRequestURL   string `json:"pullRequestUrl"`
}

// FixResult is the outcome of Fix.
type FixResult struct {
	// StillRunning is true when fix generation did not end before the deadline.
	StillRunning bool
	// Diff is the proposed change. It is empty for a type with no diff route.
	Diff json.RawMessage
	// PullRequest is set when the caller asked to wait for a pull request.
	PullRequest *PullRequestStatus
}

// PullRequestStatus is the pull-request phase of an autofix run.
type PullRequestStatus struct {
	State        string `json:"state,omitempty"`
	URL          string `json:"url,omitempty"`
	StillRunning bool   `json:"stillRunning,omitempty"`
}

// Fix starts the autofix agent for a finding, waits for it to end and returns
// the diff. The fix run opens any pull request itself, so waitForPR only waits
// for that pull request and reports it.
func Fix(ctx context.Context, c *api.Client, typeName, findingID string, waitForPR bool) (FixResult, error) {
	t, err := Lookup(typeName)
	if err != nil {
		return FixResult{}, err
	}
	if t.AutofixFix == nil {
		return FixResult{}, fmt.Errorf("autofix of type %q: %w", typeName, ErrUnsupported)
	}
	if findingID == "" {
		return FixResult{}, ErrFindingIDRequired
	}

	if _, err := t.AutofixFix(ctx, c, findingID, nil); err != nil {
		return FixResult{}, fmt.Errorf("trigger autofix: %w", err)
	}

	if _, err := pollAutofix(ctx, c, t, findingID, false); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return FixResult{StillRunning: true}, nil
		}
		return FixResult{}, err
	}

	var result FixResult
	if t.AutofixDiff != nil {
		result.Diff, err = t.AutofixDiff(ctx, c, findingID, nil)
		if err != nil {
			return FixResult{}, fmt.Errorf("get autofix diff: %w", err)
		}
	}

	if waitForPR {
		status, err := pollAutofix(ctx, c, t, findingID, true)
		switch {
		case errors.Is(err, context.DeadlineExceeded):
			result.PullRequest = &PullRequestStatus{StillRunning: true}
		case err != nil:
			return FixResult{}, err
		default:
			result.PullRequest = &PullRequestStatus{State: status.PullRequestState, URL: status.PullRequestURL}
		}
	}
	return result, nil
}

// autofixPhaseDone reports whether the watched autofix phase has ended, with the
// server-computed terminal flag as the authority.
func autofixPhaseDone(st AutofixStatus, watchPR bool) bool {
	if watchPR {
		return st.PullRequestURL != "" || (st.Terminal && st.State != autoFixStateCached)
	}
	return st.Terminal
}

// pollAutofix polls the autofix status route until the watched phase ends or the
// deadline passes. On the deadline it returns context.DeadlineExceeded.
func pollAutofix(ctx context.Context, c *api.Client, t Type, findingID string, watchPR bool) (AutofixStatus, error) {
	deadline := time.Now().Add(autofixPollDeadline)
	var last AutofixStatus
	for {
		data, err := t.AutofixStatus(ctx, c, findingID, nil)
		if err != nil {
			return last, fmt.Errorf("poll autofix status: %w", err)
		}

		var wrapper struct {
			Status AutofixStatus `json:"status"`
		}
		if err := json.Unmarshal(data, &wrapper); err == nil {
			last = wrapper.Status
		}

		if autofixPhaseDone(last, watchPR) {
			return last, nil
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
