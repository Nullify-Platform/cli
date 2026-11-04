package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
)

// Errors that Search returns before it calls the API.
var (
	ErrInvalidLimit  = errors.New("limit must be greater than zero")
	ErrInvalidStatus = errors.New("invalid status")
	ErrInvalidTime   = errors.New("invalid time")
)

// Statuses are the values that SearchOptions.Status accepts.
var Statuses = []string{"open", "fixed", "false_positive", "accepted_risk"}

// SearchOptions are the filters of the unified /admin/findings search.
type SearchOptions struct {
	// APITypes are FindingType values. Empty means all types.
	APITypes []string
	// Severity is a lower-case value, which is sent upper-case.
	Severity   string
	Repository string
	Status     string
	// From and To are RFC 3339 bounds on the finding date.
	From string
	To   string
	// Limit is the most findings to collect across pages.
	Limit int
	// Debug receives one line per page when it is not nil.
	Debug io.Writer
}

// SearchResult holds the collected findings and their completeness signals. An
// empty result has Total 0 and Truncated false. A failure to read is an error
// and never an empty result.
type SearchResult struct {
	Findings []json.RawMessage `json:"findings"`
	// Total is the count that the server reports for the filters.
	Total int `json:"total"`
	// Returned is the number of entries in Findings.
	Returned int `json:"returned"`
	// Truncated is true when the server holds more findings than Findings has.
	Truncated bool `json:"truncated"`
}

// searchPage holds the parts of a response that Search reads. Each finding stays as
// the server sent it.
type searchPage struct {
	Findings    []json.RawMessage `json:"findings"`
	Total       int               `json:"total"`
	HasMoreData bool              `json:"hasMoreData"`
}

// Search collects findings from POST /admin/findings up to opts.Limit. The page
// size stays constant across pages, because the server computes its offset from
// page and pageSize. The number of pages is bounded because every page must add
// a finding.
func Search(ctx context.Context, c *api.Client, opts SearchOptions) (SearchResult, error) {
	if opts.Limit <= 0 {
		return SearchResult{}, fmt.Errorf("%w: %d", ErrInvalidLimit, opts.Limit)
	}

	query, err := opts.query()
	if err != nil {
		return SearchResult{}, err
	}

	pageSize := min(max(opts.Limit, 20), 100)
	result := SearchResult{Findings: make([]json.RawMessage, 0)}
	hasMore := true

	for page := 1; hasMore && len(result.Findings) < opts.Limit; page++ {
		query.Page, query.PageSize = &page, &pageSize

		body, err := c.CreateAdminFindingsRaw(ctx, query)
		if err != nil {
			return SearchResult{}, err
		}

		var out searchPage
		if err := json.Unmarshal(body, &out); err != nil {
			return SearchResult{}, fmt.Errorf("%w: %w", ErrUnreadableResponse, err)
		}
		if out.Findings == nil {
			return SearchResult{}, fmt.Errorf("%w: no findings field", ErrUnreadableResponse)
		}

		if opts.Debug != nil {
			fmt.Fprintf(opts.Debug, "[debug] POST /admin/findings page %d: %d findings, hasMoreData=%v, total=%d\n", page, len(out.Findings), out.HasMoreData, out.Total)
		}

		result.Findings = append(result.Findings, out.Findings...)
		result.Total = out.Total
		hasMore = out.HasMoreData
		if len(out.Findings) == 0 {
			break
		}
	}

	if len(result.Findings) > opts.Limit {
		result.Findings = result.Findings[:opts.Limit]
	}
	result.Returned = len(result.Findings)
	result.Truncated = hasMore || result.Total > result.Returned
	return result, nil
}

func (o SearchOptions) query() (models.ModelsUnifiedFindingsQuery, error) {
	query := models.ModelsUnifiedFindingsQuery{Type: o.APITypes}
	if o.Repository != "" {
		query.Repository = repositoryNames(o.Repository)
	}
	if o.Severity != "" {
		query.Severity = []string{strings.ToUpper(o.Severity)}
	}
	if o.From != "" {
		if err := checkFilterTime("from", o.From); err != nil {
			return query, err
		}
		query.FromDate = &o.From
	}
	if o.To != "" {
		if err := checkFilterTime("to", o.To); err != nil {
			return query, err
		}
		query.ToDate = &o.To
	}

	yes, no := true, false
	switch o.Status {
	case "":
	case "open":
		query.IsResolved = &no
	case "fixed":
		query.IsFixed = &yes
	case "false_positive":
		query.IsFalsePositive = &yes
	case "accepted_risk":
		query.IsAllowlisted = &yes
	default:
		return query, fmt.Errorf("%w %q, valid statuses: %s", ErrInvalidStatus, o.Status, strings.Join(Statuses, ", "))
	}
	return query, nil
}

// checkFilterTime rejects a time that the server cannot parse. The server ignores
// such a filter, and the search then returns findings outside the window. A plain
// date is rejected, because it does not say which end of the day "to" means.
func checkFilterTime(name, value string) error {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05"} {
		if _, err := time.Parse(layout, value); err == nil {
			return nil
		}
	}
	return fmt.Errorf("%w for %s: %q, use RFC 3339 such as 2026-11-01T00:00:00Z", ErrInvalidTime, name, value)
}

// repositoryNames returns the filter values for a repository. The server matches
// them exactly: most findings hold the bare name, and a pentest finding holds the
// full name if it has one. With only one of the two, the other findings do not match.
func repositoryNames(repo string) []string {
	name := repo[strings.LastIndex(repo, "/")+1:]
	if name == repo {
		return []string{repo}
	}
	return []string{repo, name}
}
