package commands

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/spf13/cobra"
)

// ApplyContextCommandDefaults installs CLI-side opinionated defaults on top of
// the generated 'context' subcommand tree. Must be called after
// RegisterContextCommands.
func ApplyContextCommandDefaults(parent *cobra.Command, getClient func() *api.Client) {
	contextCmd := findChild(parent, "context")
	if contextCmd == nil {
		return
	}

	// `nullify api context get-project <repo> <project>` with no selectors
	// returns the latest SBOM only. Why this is non-trivial:
	//   - The underlying List endpoint defaults to pageSize=100 with ascending
	//     sort, which routinely exceeds API Gateway's 6 MB cap (opaque 500).
	//   - Dropping pageSize to 1 returns the *oldest* SBOM, not the latest,
	//     because the storage default sort is ascending.
	//   - The /repository/{id}/latest endpoint also returns full SBOM payloads
	//     (one per project), and blows the same cap on repos with many
	//     projects.
	// The cheapest workaround is two small calls: list-tree (metadata only,
	// hundreds of KB at most) to find the newest commit SHA for this specific
	// project, then the single-commit fast path on the existing endpoint.
	if cmd := findChild(contextCmd, "get-project"); cmd != nil {
		orig := cmd.RunE
		cmd.RunE = func(c *cobra.Command, args []string) error {
			if contextGetProjectHasSelector(c) || len(args) < 2 {
				return orig(c, args)
			}
			latest, err := latestCommitForProject(c, getClient(), args[0], args[1])
			if err != nil {
				return err
			}
			if err := c.Flags().Set("from-commit", latest); err != nil {
				return err
			}
			if err := c.Flags().Set("until-commit", latest); err != nil {
				return err
			}
			return orig(c, args)
		}
	}
}

// latestCommitForProject finds the most recent commit SHA for the given
// (repository, project) by reading the SBOM key tree. The tree stores commits
// in ascending order (oldest first), so the newest is the last element.
func latestCommitForProject(cmd *cobra.Command, client *api.Client, repoID, projectID string) (string, error) {
	raw, err := client.ListContextSbomsTree(cmd.Context(), url.Values{})
	if err != nil {
		return "", fmt.Errorf("list sbom tree: %w", err)
	}

	var tree struct {
		Repositories []struct {
			RepositoryID string `json:"repositoryId"`
			Projects     []struct {
				ProjectID string   `json:"projectId"`
				Commits   []string `json:"commits"`
			} `json:"projects"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(raw, &tree); err != nil {
		return "", fmt.Errorf("decode sbom tree: %w", err)
	}

	for _, r := range tree.Repositories {
		if r.RepositoryID != repoID {
			continue
		}
		for _, p := range r.Projects {
			if p.ProjectID != projectID {
				continue
			}
			if len(p.Commits) == 0 {
				return "", fmt.Errorf("no SBOMs found for repository %s, project %s", repoID, projectID)
			}
			return p.Commits[len(p.Commits)-1], nil
		}
	}
	return "", fmt.Errorf("repository %s, project %s not found in SBOM tree", repoID, projectID)
}

func findChild(parent *cobra.Command, name string) *cobra.Command {
	if parent == nil {
		return nil
	}
	for _, c := range parent.Commands() {
		if c.Name() == name {
			return c
		}
	}
	return nil
}

func contextGetProjectHasSelector(cmd *cobra.Command) bool {
	for _, name := range []string{"page", "page-size", "from-commit", "until-commit", "from-time", "until-time"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			return true
		}
	}
	return false
}
