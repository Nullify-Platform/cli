package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

var reposCmd = &cobra.Command{
	Use:     "repos",
	Short:   "List monitored repositories",
	Long:    "List every monitored repository. The command reads all pages of the listing.",
	Example: "  nullify repos\n  nullify repos -o table",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		authCtx, err := resolveCommandAuth(ctx)
		if err != nil {
			return err
		}
		apiClient := authCtx.APIClient()

		result, err := listAllRepositories(ctx, apiClient)
		if err != nil {
			return err
		}

		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if err := output.Print(cmd, data); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), string(data))
		}
		return nil
	},
}

// listAllRepositories reads every page of GET /context/repositories, which
// returns 100 repositories a page by default, and returns them as one page
// with no next token.
func listAllRepositories(ctx context.Context, c *api.Client) (*models.EndpointsGetRepositoriesOutput, error) {
	all := &models.EndpointsGetRepositoriesOutput{}
	seen := map[string]bool{}
	var token *string
	for {
		page, err := c.ListContextRepositories(ctx, api.ListContextRepositoriesInput{NextToken: token})
		if err != nil {
			return nil, err
		}
		all = appendRepositoryPage(all, page)

		next := page.NextToken
		if next == "" {
			return all, nil
		}
		if seen[next] {
			return nil, fmt.Errorf("listing repositories: the server repeated page token %q", next)
		}
		seen[next] = true
		token = &next
	}
}

// appendRepositoryPage returns a new listing with page added to all.
func appendRepositoryPage(
	all, page *models.EndpointsGetRepositoriesOutput,
) *models.EndpointsGetRepositoriesOutput {
	repositories := make([]models.RepocontextRepoContext, 0, len(all.Repositories)+len(page.Repositories))
	repositories = append(repositories, all.Repositories...)
	repositories = append(repositories, page.Repositories...)

	var ids map[string]string
	if len(all.RepositoryIds)+len(page.RepositoryIds) > 0 {
		ids = make(map[string]string, len(all.RepositoryIds)+len(page.RepositoryIds))
		maps.Copy(ids, all.RepositoryIds)
		maps.Copy(ids, page.RepositoryIds)
	}

	return &models.EndpointsGetRepositoriesOutput{
		Repositories:  repositories,
		RepositoryIds: ids,
		NumItems:      len(repositories),
		Version:       page.Version,
	}
}

func init() {
	rootCmd.AddCommand(reposCmd)
}
