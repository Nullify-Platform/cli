package lib

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DetectRepoFromGit reads the git remote origin URL from the nearest .git/config
// and extracts the repository name.
func DetectRepoFromGit() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		gitConfig := filepath.Join(dir, ".git", "config")
		if _, err := os.Stat(gitConfig); err == nil {
			return ParseRepoFromGitConfig(gitConfig)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return ""
}

// ParseRepoFromGitConfig extracts the repo name from a .git/config file.
func ParseRepoFromGitConfig(path string) string {
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
				return ExtractRepoName(strings.TrimSpace(parts[1]))
			}
		}
	}

	return ""
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
