package findings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
)

// Errors that Search returns before it calls the API.
var (
	ErrInvalidLimit  = errors.New("limit must be greater than zero")
	ErrInvalidStatus = errors.New("invalid status")
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

		out, err := c.CreateAdminFindings(ctx, api.CreateAdminFindingsInput{Query: query})
		if err != nil {
			return SearchResult{}, err
		}

		if opts.Debug != nil {
			fmt.Fprintf(opts.Debug, "[debug] POST /admin/findings page %d: %d findings, hasMoreData=%v, total=%d\n", page, len(out.Findings), out.HasMoreData, out.Total)
		}

		for _, finding := range out.Findings {
			raw, err := json.Marshal(finding)
			if err != nil {
				return SearchResult{}, err
			}
			result.Findings = append(result.Findings, raw)
		}

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
		query.Repository = []string{o.Repository}
	}
	if o.Severity != "" {
		query.Severity = []string{strings.ToUpper(o.Severity)}
	}
	if o.From != "" {
		query.FromDate = &o.From
	}
	if o.To != "" {
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
