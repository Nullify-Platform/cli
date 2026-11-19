package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
)

// maxSBOMBytes bounds one downloaded SBOM document.
const maxSBOMBytes = 512 << 20

// projectCommit names the newest SBOM of one project.
type projectCommit struct {
	projectID string
	commit    string
}

// LatestSBOMs returns the newest SBOM of every project in the repository, or
// of projectID alone when it is set.
//
// GET .../latest and the project listing both return whole documents, and a
// large repository's documents exceed the 6 MB cap on a Lambda response, which
// fails the read with an opaque 500. The listing also starts with the oldest
// SBOM. So this reads the newest commit of each project from the SBOM tree,
// which holds no documents, then asks for that one document as a presigned
// URL and downloads it with download, which never carries the API token.
func LatestSBOMs(
	ctx context.Context, c *api.Client, download *http.Client, repoID, projectID string,
) (*models.EndpointsGetLatestSBOMsOutput, error) {
	tree, err := c.ListContextSbomsTree(ctx, api.ListContextSbomsTreeInput{})
	if err != nil {
		return nil, fmt.Errorf("list sbom tree: %w", err)
	}
	commits, err := newestSBOMCommits(tree, repoID, projectID)
	if err != nil {
		return nil, err
	}

	out := &models.EndpointsGetLatestSBOMsOutput{
		Version: tree.Version,
		Sboms:   []models.ModelsCDXGenAtCommit{},
	}
	for _, pc := range commits {
		sboms, err := sbomAtCommit(ctx, c, download, repoID, pc)
		if err != nil {
			return nil, err
		}
		out.Sboms = append(out.Sboms, sboms...)
	}
	return out, nil
}

// newestSBOMCommits returns the newest commit of each project of the
// repository in the tree, or of projectID alone when it is set. The tree
// lists commits oldest first, so the newest is the last.
func newestSBOMCommits(tree *models.EndpointsGetSBOMTreeOutput, repoID, projectID string) ([]projectCommit, error) {
	for _, r := range tree.Repositories {
		if r.RepositoryID != repoID {
			continue
		}
		if projectID != "" {
			return newestProjectCommit(r, projectID)
		}
		var commits []projectCommit
		for _, p := range r.Projects {
			if len(p.Commits) > 0 {
				commits = append(commits, projectCommit{projectID: p.ProjectID, commit: p.Commits[len(p.Commits)-1]})
			}
		}
		if len(commits) > 0 {
			return commits, nil
		}
	}
	if projectID != "" {
		return nil, fmt.Errorf("repository %s, project %s not found in SBOM tree", repoID, projectID)
	}
	return nil, fmt.Errorf("no SBOMs found for repository %s", repoID)
}

func newestProjectCommit(r models.ModelsSBOMRepository, projectID string) ([]projectCommit, error) {
	for _, p := range r.Projects {
		if p.ProjectID != projectID {
			continue
		}
		if len(p.Commits) == 0 {
			return nil, fmt.Errorf("no SBOMs found for repository %s, project %s", r.RepositoryID, projectID)
		}
		return []projectCommit{{projectID: projectID, commit: p.Commits[len(p.Commits)-1]}}, nil
	}
	return nil, fmt.Errorf("repository %s, project %s not found in SBOM tree", r.RepositoryID, projectID)
}

// sbomAtCommit reads one project's SBOM at one commit. A server that does not
// know preferUrl answers with the document inline, which is used as is.
func sbomAtCommit(
	ctx context.Context, c *api.Client, download *http.Client, repoID string, pc projectCommit,
) ([]models.ModelsCDXGenAtCommit, error) {
	preferURL := true
	commit := pc.commit
	resp, err := c.GetContextSbomsRepositoryRepositoryIdProjectProjectId(ctx,
		api.GetContextSbomsRepositoryRepositoryIdProjectProjectIdInput{
			RepositoryID: repoID,
			ProjectID:    pc.projectID,
			FromCommit:   &commit,
			UntilCommit:  &commit,
			PreferURL:    &preferURL,
		})
	if err != nil {
		return nil, fmt.Errorf("get sbom for project %s at commit %s: %w", pc.projectID, pc.commit, err)
	}
	if len(resp.Urls) == 0 {
		return resp.Sboms, nil
	}

	sboms := make([]models.ModelsCDXGenAtCommit, 0, len(resp.Urls))
	for _, u := range resp.Urls {
		sbom, err := downloadSBOM(ctx, download, u.URL)
		if err != nil {
			return nil, fmt.Errorf("download sbom for project %s at commit %s: %w", pc.projectID, u.CommitSha, err)
		}
		// The stored document does not carry its commit; the listing does.
		sbom.CommitSha = u.CommitSha
		sboms = append(sboms, sbom)
	}
	return sboms, nil
}

// downloadSBOM fetches one presigned SBOM document. The URL must be https.
func downloadSBOM(ctx context.Context, hc *http.Client, rawURL string) (models.ModelsCDXGenAtCommit, error) {
	var sbom models.ModelsCDXGenAtCommit

	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return sbom, fmt.Errorf("the server returned an SBOM URL that is not https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return sbom, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		// Transport and redirect errors can contain the signed URL.
		if ctx.Err() != nil {
			return sbom, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return sbom, context.DeadlineExceeded
		}
		return sbom, errors.New("request to the SBOM document store failed")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return sbom, fmt.Errorf("document store returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSBOMBytes+1))
	if err != nil {
		return sbom, err
	}
	if len(body) > maxSBOMBytes {
		return sbom, fmt.Errorf("SBOM document is larger than %d MB", maxSBOMBytes>>20)
	}
	if err := json.Unmarshal(body, &sbom); err != nil {
		return sbom, fmt.Errorf("decode SBOM document: %w", err)
	}
	return sbom, nil
}
