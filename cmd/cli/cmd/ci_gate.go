package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
)

// gateCheck is one list the gate reads: a scanner and, for a scanner the
// server filters by severity, one severity value.
type gateCheck struct {
	ep       scannerEndpoint
	severity string
}

// gateResult is the outcome of one gateCheck.
type gateResult struct {
	check   gateCheck
	blocked bool
	err     error
}

func gateChecks(endpoints []scannerEndpoint, severities []string) []gateCheck {
	checks := []gateCheck{}
	for _, ep := range endpoints {
		for _, severity := range scannerSeverities(ep, severities) {
			checks = append(checks, gateCheck{ep: ep, severity: severity})
		}
	}
	return checks
}

// runGateChecks runs every check concurrently and returns the results in the
// order of checks.
func runGateChecks(
	ctx context.Context,
	get findingsGetter,
	base map[string]string,
	checks []gateCheck,
	threshold severityLevel,
	repo string,
) []gateResult {
	results := make([]gateResult, len(checks))
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Go(func() {
			results[i] = runGateCheck(ctx, get, base, check, threshold, repo)
		})
	}
	wg.Wait()
	return results
}

// runGateCheck reads one list until a finding blocks the gate or the list
// ends. It stops at the first blocking finding, because one is enough to
// fail the gate.
func runGateCheck(
	ctx context.Context,
	get findingsGetter,
	base map[string]string,
	check gateCheck,
	threshold severityLevel,
	repo string,
) gateResult {
	blocked := false
	err := visitFindingPages(
		ctx, get, check.ep.path, base,
		scannerQueryParams(check.ep, check.severity, repo),
		func(page []json.RawMessage) bool {
			blocked = slices.ContainsFunc(page, func(finding json.RawMessage) bool {
				return blocksGate(check.ep, finding, threshold)
			})
			return !blocked
		},
	)
	return gateResult{check: check, blocked: blocked, err: err}
}

// blocksGate reports whether a finding fails the gate at the threshold.
func blocksGate(ep scannerEndpoint, finding json.RawMessage, threshold severityLevel) bool {
	return findingSeverity(ep, finding).meets(threshold)
}

// gateVerdict prints the result of every check and returns the gate's error.
// A list that could not be read fails the gate even when the others are
// clean, because the gate cannot confirm a clean result without it.
func gateVerdict(results []gateResult, threshold severityLevel) error {
	var failed, unreadable, blocked int
	for _, result := range results {
		label := scannerLabel(result.check.ep, result.check.severity)
		switch {
		case isUnreadable(result.err):
			unreadable++
			fmt.Fprintf(os.Stderr, "Error: unreadable response from %s: %v\n", label, result.err)
		case result.err != nil:
			failed++
			fmt.Fprintf(os.Stderr, "Warning: failed to query %s: %v\n", label, result.err)
		case result.blocked:
			blocked++
			fmt.Println(gateFailLine(result.check, threshold))
		}
	}

	switch {
	case failed > 0:
		return networkError("%d scanner request(s) failed; failing the gate (cannot confirm a clean result)", failed)
	case unreadable > 0:
		return networkError("%d scanner response(s) could not be read; failing the gate (cannot confirm a clean result)", unreadable)
	case blocked > 0:
		fmt.Printf("\nGate failed: open findings at or above %s severity\n", threshold)
		return withExitCode(ExitFindings, fmt.Errorf("gate failed: open findings at or above %s severity", threshold))
	default:
		return nil
	}
}

// isUnreadable reports a list whose responses could not be read in full.
func isUnreadable(err error) bool {
	return errors.Is(err, errUnreadableFindings) || errors.Is(err, errTooManyFindingPages)
}

// gateFailLine reports a check that found a blocking finding.
func gateFailLine(check gateCheck, threshold severityLevel) string {
	switch {
	case check.severity != "":
		return fmt.Sprintf("FAIL: %s has open %s findings", check.ep.name, check.severity)
	case len(check.ep.severityFields) == 0:
		return fmt.Sprintf("FAIL: %s has open findings (its findings carry no severity, so every open one counts)", check.ep.name)
	default:
		return fmt.Sprintf("FAIL: %s has open findings at or above %s severity", check.ep.name, threshold)
	}
}
