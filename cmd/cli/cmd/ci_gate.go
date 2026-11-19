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
	// unnarrowed counts findings of other repositories on a list the server
	// was asked to narrow to the scope's repository.
	unnarrowed int
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
	scope repositoryScope,
) []gateResult {
	results := make([]gateResult, len(checks))
	var wg sync.WaitGroup
	for i, check := range checks {
		wg.Go(func() {
			results[i] = runGateCheck(ctx, get, base, check, threshold, scope)
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
	scope repositoryScope,
) gateResult {
	blocked, outOfScope := false, 0
	err := visitFindingPages(
		ctx, get, check.ep.path, base,
		scannerQueryParams(check.ep, check.severity, scope),
		func(page []json.RawMessage) bool {
			outOfScope += countOutOfScope(check.ep, scope, page)
			blocked = slices.ContainsFunc(page, func(finding json.RawMessage) bool {
				return blocksGate(check.ep, scope, finding, threshold)
			})
			return !blocked
		},
	)
	result := gateResult{check: check, blocked: blocked, err: err}
	if len(scope.queryParams(check.ep)) > 0 {
		result.unnarrowed = outOfScope
	}
	return result
}

// countOutOfScope counts the findings of a page that belong to another
// repository.
func countOutOfScope(ep scannerEndpoint, scope repositoryScope, page []json.RawMessage) int {
	count := 0
	for _, finding := range page {
		if !scope.includes(ep, finding) {
			count++
		}
	}
	return count
}

// blocksGate reports whether a finding fails the gate at the threshold.
func blocksGate(ep scannerEndpoint, scope repositoryScope, finding json.RawMessage, threshold severityLevel) bool {
	return countsForScanner(ep, scope, finding) && findingSeverity(ep, finding).meets(threshold)
}

// gateVerdict prints the result of every check and returns the gate's error.
// A list that could not be read fails the gate even when the others are
// clean, because the gate cannot confirm a clean result without it.
func gateVerdict(results []gateResult, threshold severityLevel) error {
	var denied, failed, unreadable, blocked int
	for _, result := range results {
		label := scannerLabel(result.check.ep, result.check.severity)
		warnUnnarrowed(label, result.unnarrowed)
		switch {
		case isAccessDenied(result.err):
			denied++
			fmt.Fprintf(os.Stderr, "Error: access refused for %s: %v\n", label, result.err)
		case errors.Is(result.err, errTooManyFindingPages):
			unreadable++
			fmt.Fprintf(os.Stderr, "Error: could not read all of %s: %v\n", label, result.err)
		case errors.Is(result.err, errUnreadableFindings):
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
	case denied > 0:
		return authError("%d scanner request(s) were refused (401 or 403); failing the gate (check the token's access)", denied)
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

// warnUnnarrowed reports a list the server did not narrow to the scope's
// repository. The CLI leaves the other repositories' findings out either
// way, but when the ID is wrong for the tenant's git provider, this
// repository's findings are missing too and the gate passes on nothing.
func warnUnnarrowed(label string, unnarrowed int) {
	if unnarrowed == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"Warning: %s returned %d finding(s) of other repositories, so the server did not narrow the list "+
			"to this repository and the CLI left them out. If this repository's findings are missing, "+
			"check that --repository-id is its ID at the tenant's git provider.\n",
		label, unnarrowed)
}

// gateFailLine reports a check that found a blocking finding.
func gateFailLine(check gateCheck, threshold severityLevel) string {
	switch {
	case check.severity == severityUnknown.String():
		return fmt.Sprintf("FAIL: %s has open findings of unknown severity", check.ep.name)
	case check.severity != "":
		return fmt.Sprintf("FAIL: %s has open %s findings", check.ep.name, check.severity)
	case len(check.ep.severityFields) == 0:
		return fmt.Sprintf("FAIL: %s has open findings (its findings carry no severity, so every open one counts)", check.ep.name)
	default:
		return fmt.Sprintf("FAIL: %s has open findings at or above %s severity", check.ep.name, threshold)
	}
}
