package lib

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// DetectRepoFromGit reads the git remote origin URL of the repository around
// the working directory and extracts the repository name.
func DetectRepoFromGit() string {
	if gitConfig := findGitConfig(); gitConfig != "" {
		return ParseRepoFromGitConfig(gitConfig)
	}
	return ""
}

// DetectOwnerFromGit reads the git remote origin URL of the repository around
// the working directory and extracts the organization that owns it.
func DetectOwnerFromGit() string {
	if gitConfig := findGitConfig(); gitConfig != "" {
		return ExtractRepoOwner(originURL(gitConfig))
	}
	return ""
}

func findGitConfig() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}

	for {
		if gitConfig := gitConfigAt(filepath.Join(dir, ".git")); gitConfig != "" {
			return gitConfig
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// gitConfigAt returns the config file of the repository whose .git is at
// dotGit: a directory in a plain clone, or a file naming the real git dir in
// a linked worktree or a submodule. A worktree shares its main repository's
// config, which its git dir names in commondir.
func gitConfigAt(dotGit string) string {
	info, err := os.Stat(dotGit)
	if err != nil {
		return ""
	}
	gitDir := dotGit
	if !info.IsDir() {
		data, err := os.ReadFile(dotGit)
		if err != nil {
			return ""
		}
		target, ok := strings.CutPrefix(strings.TrimSpace(string(data)), "gitdir:")
		if !ok {
			return ""
		}
		gitDir = strings.TrimSpace(target)
		if !filepath.IsAbs(gitDir) {
			gitDir = filepath.Join(filepath.Dir(dotGit), gitDir)
		}
		if common, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
			commonDir := strings.TrimSpace(string(common))
			if !filepath.IsAbs(commonDir) {
				commonDir = filepath.Join(gitDir, commonDir)
			}
			gitDir = commonDir
		}
	}
	gitConfig := filepath.Join(gitDir, "config")
	if _, err := os.Stat(gitConfig); err != nil {
		return ""
	}
	return gitConfig
}

// ParseRepoFromGitConfig extracts the repo name from a .git/config file.
func ParseRepoFromGitConfig(path string) string {
	if url := originURL(path); url != "" {
		return ExtractRepoName(url)
	}
	return ""
}

// originURL returns the url of remote "origin" in a .git/config file.
func originURL(path string) string {
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

// ExtractRepoOwner extracts the owning organization from a git remote URL: the
// first path segment after the host, which is the GitHub org, GitLab group,
// Bitbucket workspace or Azure DevOps organization. Handles SCP-style SSH
// (git@github.com:org/repo.git), ssh:// and https:// forms, and Azure's
// "v3/" SSH prefix. Returns "" when the URL names no owner.
func ExtractRepoOwner(remoteURL string) string {
	remoteURL = strings.TrimSpace(remoteURL)

	var path string
	if i := strings.Index(remoteURL, "://"); i >= 0 {
		rest := remoteURL[i+3:]
		slash := strings.Index(rest, "/")
		if slash < 0 {
			return ""
		}
		path = rest[slash+1:]
	} else if at := strings.Index(remoteURL, ":"); at >= 0 && !strings.Contains(remoteURL[:at], "/") {
		path = remoteURL[at+1:]
	} else {
		return ""
	}

	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) > 1 && segments[0] == "v3" && strings.Contains(remoteURL, "dev.azure.com") {
		segments = segments[1:]
	}
	if len(segments) < 2 || segments[0] == "" {
		return ""
	}
	return segments[0]
}
