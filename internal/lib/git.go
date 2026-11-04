package lib

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DetectRepoFromGit reads the git remote origin URL from the nearest .git/config
// and returns the repository name.
func DetectRepoFromGit() string {
	return ParseRepoFromGitConfig(nearestGitConfig())
}

// DetectRepoFullNameFromGit is DetectRepoFromGit for callers that also need the
// owner. It returns owner/name when the remote URL holds both, otherwise the name.
func DetectRepoFullNameFromGit() string {
	return ExtractRepoFullName(originURLFromGitConfig(nearestGitConfig()))
}

// nearestGitConfig returns the path of the .git/config file at or above the working
// directory, or an empty string if there is none.
func nearestGitConfig() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		gitConfig := filepath.Join(dir, ".git", "config")
		if _, err := os.Stat(gitConfig); err == nil {
			return gitConfig
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// ParseRepoFromGitConfig extracts the repo name from a .git/config file.
func ParseRepoFromGitConfig(path string) string {
	return ExtractRepoName(originURLFromGitConfig(path))
}

// originURLFromGitConfig returns the URL of the origin remote in a .git/config file.
func originURLFromGitConfig(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	inOrigin := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == `[remote "origin"]` {
			inOrigin = true
			continue
		}

		if strings.HasPrefix(line, "[") {
			inOrigin = false
			continue
		}

		if inOrigin && strings.HasPrefix(line, "url") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

// ExtractRepoFullName extracts the path of the repository from a git remote URL:
// owner/name for most hosts. It returns an empty string for an empty URL.
func ExtractRepoFullName(remoteURL string) string {
	remoteURL = strings.TrimSuffix(remoteURL, ".git")

	if strings.HasPrefix(remoteURL, "git@") {
		_, path, _ := strings.Cut(remoteURL, ":")
		return path
	}

	parsed, err := url.Parse(remoteURL)
	if err != nil {
		return ExtractRepoName(remoteURL)
	}
	return strings.Trim(parsed.Path, "/")
}

// ExtractRepoName extracts the repository name from a git remote URL.
// Handles both SSH (git@github.com:org/repo.git) and HTTPS (https://github.com/org/repo.git) formats.
func ExtractRepoName(remoteURL string) string {
	remoteURL = strings.TrimSuffix(remoteURL, ".git")

	// SSH format: git@github.com:org/repo
	if strings.Contains(remoteURL, ":") && strings.HasPrefix(remoteURL, "git@") {
		parts := strings.SplitN(remoteURL, ":", 2)
		if len(parts) == 2 {
			pathParts := strings.Split(parts[1], "/")
			if len(pathParts) > 0 {
				return pathParts[len(pathParts)-1]
			}
		}
	}

	// HTTPS format: https://github.com/org/repo
	parts := strings.Split(remoteURL, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}

	return ""
}
