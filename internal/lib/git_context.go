package lib

import (
	"os/exec"
	"strings"
)

// GitContext contains auto-detected git information.
type GitContext struct {
	Repository string // org/repo format
	Branch     string
	CommitSHA  string
}

// DetectGitContext auto-detects repository, branch, and commit SHA from the current git repo.
func DetectGitContext() GitContext {
	ctx := GitContext{}
	ctx.Repository = DetectRepoFromGit()
	ctx.Branch = detectBranch()
	ctx.CommitSHA = detectCommitSHA()
	return ctx
}

func detectBranch() string {
	out, err := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func detectCommitSHA() string {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
