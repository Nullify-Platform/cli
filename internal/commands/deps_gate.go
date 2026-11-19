package commands

import (
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/scan"
)

// Verdict is a dependency malware-analysis verdict as returned by
// vuln-database (passed through scpm). The recognised set is below; any
// other non-empty verdict is treated as unknown and fails closed (see
// classifyVerdict) so a server-side rename can't silently bypass the gate.
// vuln-database writes confirmed_malicious, suspicious, benign and
// inconclusive. vulnerable is kept for the --fail-on=vulnerable threshold.
type Verdict string

const (
	VerdictBenign       Verdict = "benign"
	VerdictVulnerable   Verdict = "vulnerable"
	VerdictSuspicious   Verdict = "suspicious"
	VerdictMalicious    Verdict = "confirmed_malicious"
	VerdictInconclusive Verdict = "inconclusive"
)

// gateOutcome is the worst result seen across analysed deps: a comparable
// rank, a human label for messaging, and the exit code to use if it ends
// up being the worst.
type gateOutcome struct {
	rank  int
	label string
	code  int
}

// depsGateResult decides the exit of a run from every dependency's outcome.
// The worst verdict is checked against --fail-on first. A dependency that
// has no usable verdict then fails the run as incomplete, because the gate
// cannot certify a dependency nobody judged. --fail-on=none never fails.
func depsGateResult(analyzed []analyzedDep, failOn string) error {
	worst := gateOutcome{}
	incomplete := 0
	for _, a := range analyzed {
		if a.Resp != nil {
			if o := classifyVerdict(a.Resp.Verdict, a.Dep); o.rank > worst.rank {
				worst = o
			}
		}
		if reason, missing := missingVerdict(a); missing {
			incomplete++
			fmt.Fprintf(os.Stderr, "  %s/%s@%s: no verdict: %s\n", a.Dep.Ecosystem, a.Dep.Name, a.Dep.Version, reason)
		}
	}

	if failOn == "none" {
		return nil
	}
	if err := checkFailOn(failOn, worst); err != nil {
		return err
	}
	if incomplete > 0 {
		return exitError(exitTransientFailure,
			"%d of %d dependency analyses returned no verdict, so the gate cannot pass; re-run with --wait, or pass --fail-on=none to only queue analyses",
			incomplete, len(analyzed))
	}
	return nil
}

// missingVerdict reports why a dependency has no verdict the gate can rely
// on, or false when it has one.
func missingVerdict(a analyzedDep) (string, bool) {
	switch {
	case a.Resp == nil:
		return "the analysis request failed", true
	case a.Resp.Verdict == VerdictInconclusive:
		return "the analysis was inconclusive", true
	case a.Resp.Verdict != "":
		return "", false
	case isTerminal(a.Resp):
		return fmt.Sprintf("the job ended %q without a verdict", a.Resp.Status), true
	default:
		return fmt.Sprintf("the job is still %q; pass --wait to wait for it", a.Resp.Status), true
	}
}

// classifyVerdict maps a verdict + its dependency to a gateOutcome.
// Recognised verdicts use their normal rank; a non-empty verdict the CLI
// doesn't recognise fails closed — it warns and is ranked as malicious so
// it crosses any --fail-on threshold except "none". An empty or
// inconclusive verdict is not a judgement of the dependency and ranks
// nothing; depsGateResult fails the run on it as incomplete instead.
func classifyVerdict(v Verdict, d scan.ChangedDep) gateOutcome {
	switch v {
	case "", VerdictInconclusive:
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
