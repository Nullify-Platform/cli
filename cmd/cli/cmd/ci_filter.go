package cmd

import (
	"encoding/json"
	"slices"
)

// closedFlags are the lifecycle fields that, when true, mark a finding as no
// longer open.
var closedFlags = []string{"isFixed", "isAllowlisted", "isArchived", "isFalsePositive"}

// isOpenFinding reports whether a finding is open: not fixed, allowlisted,
// archived or a false positive, and not superseded by a later scan. A
// finding that cannot be read counts as open, so the gate does not pass a
// finding it could not inspect.
func isOpenFinding(finding json.RawMessage) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(finding, &fields); err != nil {
		return true
	}
	for _, name := range closedFlags {
		if value, ok := boolField(fields, name); ok && value {
			return false
		}
	}
	latest, ok := boolField(fields, "isLatest")
	return !ok || latest
}

// boolField reads a boolean field. It reports false for a field that is
// missing, null or not a boolean.
func boolField(fields map[string]json.RawMessage, name string) (value bool, ok bool) {
	var parsed *bool
	if err := json.Unmarshal(fields[name], &parsed); err != nil || parsed == nil {
		return false, false
	}
	return *parsed, true
}

// countsForScanner reports whether the gate and the report count a finding
// of this scanner. A scanner whose list route returns closed findings too
// has them dropped here, and so does a finding of another repository.
func countsForScanner(ep scannerEndpoint, scope repositoryScope, finding json.RawMessage) bool {
	if ep.filtersOpenOnClient && !isOpenFinding(finding) {
		return false
	}
	return scope.includes(ep, finding)
}

// countedFindings returns the findings of a list that the gate and the
// report count, in their original order.
func countedFindings(ep scannerEndpoint, scope repositoryScope, findings []json.RawMessage) []json.RawMessage {
	return slices.DeleteFunc(slices.Clone(findings), func(finding json.RawMessage) bool {
		return !countsForScanner(ep, scope, finding)
	})
}
