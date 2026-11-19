package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/nullify-platform/cli/internal/findings"
)

// Defaults are what the server applies to a call that does not set them. They
// are fixed when the server starts.
type Defaults struct {
	// Repository filters findings searches and metrics by default. It comes
	// from --repo or from the git remote of the working directory, and is
	// empty when the server started for no repository.
	Repository string
}

// allRepositories is the repository argument that searches every repository
// instead of the default one.
const allRepositories = "*"

// searchRepository returns the repository filter for a findings search of
// apiTypes. An explicit repository wins and * means every repository. With
// neither, the default applies to types whose findings can have a repository:
// cloud and bug hunt findings have none, so the default would remove them all.
func (d Defaults) searchRepository(explicit string, apiTypes []string) string {
	switch {
	case explicit == allRepositories:
		return ""
	case explicit != "":
		return explicit
	case findings.HasRepository(apiTypes):
		return d.Repository
	default:
		return ""
	}
}

// metricsRepository returns the repository filter of a metrics query: the
// filter values of the default repository, or nil for every repository.
func (d Defaults) metricsRepository() []string {
	if d.Repository == "" {
		return nil
	}
	return findings.RepositoryFilter(d.Repository)
}

// repositoryNote tells the caller that a result is filtered to the default
// repository, and how to search every repository instead.
func repositoryNote(repo string) string {
	return "Repository: " + repo + ", the default this server started with. Pass repository " + allRepositories + " to search every repository."
}

// metricsNote tells the caller that metrics are filtered to the default
// repository.
func metricsNote(repo string) string {
	return "Repository: " + repo + ", the default this server started with. Cloud and bug hunt findings have no repository, so these metrics leave them out."
}

// fanOutNote tells the caller that searches across the finding types used the
// default repository, and "" when the server has none.
func (d Defaults) fanOutNote() string {
	if d.Repository == "" {
		return ""
	}
	return "Repository: " + d.Repository + ", the default this server started with. Cloud and bug hunt findings have no repository, so they are included for every repository."
}

// metricsRepositoryNote returns the note for metrics that the default
// repository filtered, and "" when the server has none.
func (d Defaults) metricsRepositoryNote() string {
	if d.Repository == "" {
		return ""
	}
	return metricsNote(d.Repository)
}

// withNote appends a text note to a successful result. An error result or an
// empty note is returned as it is.
func withNote(result *mcp.CallToolResult, note string) *mcp.CallToolResult {
	if result == nil || result.IsError || note == "" {
		return result
	}
	updated := *result
	updated.Content = append(append([]mcp.Content(nil), result.Content...), mcp.NewTextContent(note))
	return &updated
}
