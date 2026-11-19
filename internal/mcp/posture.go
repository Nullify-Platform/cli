package mcp

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/findings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// postureSeverities are the severities that the posture summary counts.
var postureSeverities = []string{"critical", "high", "medium", "low"}

// postureConcurrency bounds the count requests that run at once.
const postureConcurrency = 6

// postureType is the open findings of one type, by severity. A type whose count
// failed has Error set and counts nothing.
type postureType struct {
	Type       string         `json:"type"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity,omitempty"`
	Error      string         `json:"error,omitempty"`
}

// postureSummary is the result of get_security_posture_summary. Total and
// BySeverity add up the types that were counted, and Complete is false when a
// type failed.
type postureSummary struct {
	Status     string         `json:"status"`
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"bySeverity"`
	Types      []postureType  `json:"types"`
	Complete   bool           `json:"complete"`
}

// postureCell is one count: a type and a severity.
type postureCell struct {
	typeIndex int
	severity  string
	count     int
	err       error
}

func registerPostureSummaryTool(s *server.MCPServer, c *api.Client, d Defaults) {
	s.AddTool(
		readOnlyTool("get_security_posture_summary",
			mcp.WithDescription("High-level security posture across all scanner types: the number of open findings of each type by severity (critical, high, medium, low), and the totals. Typically the first tool to call to understand overall state. "+findingsSearchScope),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			summary := summarizePosture(countPosture(ctx, c, d))
			out, err := json.MarshalIndent(summary, "", "  ")
			if err != nil {
				return toolError(err), nil
			}
			return withNote(toolResult(string(out)), d.fanOutNote()), nil
		},
	)
}

// countPosture counts the open findings of every scanner type and severity.
// Each count reads one finding, and at most postureConcurrency run at once.
func countPosture(ctx context.Context, c *api.Client, d Defaults) []postureCell {
	cells := make([]postureCell, 0, len(scannerTypes)*len(postureSeverities))
	for i := range scannerTypes {
		for _, severity := range postureSeverities {
			cells = append(cells, postureCell{typeIndex: i, severity: severity})
		}
	}

	results := make([]postureCell, len(cells))
	slots := make(chan struct{}, postureConcurrency)
	var wg sync.WaitGroup
	for i, cell := range cells {
		wg.Add(1)
		go func(i int, cell postureCell) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i] = countCell(ctx, c, d, cell)
		}(i, cell)
	}
	wg.Wait()
	return results
}

func countCell(ctx context.Context, c *api.Client, d Defaults, cell postureCell) postureCell {
	apiTypes := findings.Types[scannerTypes[cell.typeIndex]].APITypes
	count, err := findings.Count(ctx, c, findings.SearchOptions{
		APITypes:   apiTypes,
		Severity:   cell.severity,
		Status:     "open",
		Repository: d.searchRepository("", apiTypes),
	})
	return postureCell{typeIndex: cell.typeIndex, severity: cell.severity, count: count, err: err}
}

// summarizePosture adds the counts up by type and by severity. A type with a
// failed count reports the first error and is left out of the totals.
func summarizePosture(cells []postureCell) postureSummary {
	types := make([]postureType, len(scannerTypes))
	for i, name := range scannerTypes {
		types[i] = postureType{Type: name, BySeverity: map[string]int{}}
	}
	for _, cell := range cells {
		entry := types[cell.typeIndex]
		if cell.err != nil && entry.Error == "" {
			entry.Error = cell.err.Error()
		}
		entry.BySeverity[cell.severity] = cell.count
		entry.Total += cell.count
		types[cell.typeIndex] = entry
	}

	summary := postureSummary{Status: "open", BySeverity: map[string]int{}, Complete: true}
	for _, severity := range postureSeverities {
		summary.BySeverity[severity] = 0
	}
	for i, entry := range types {
		if entry.Error != "" {
			types[i] = postureType{Type: entry.Type, Error: entry.Error}
			summary.Complete = false
			continue
		}
		summary.Total += entry.Total
		for severity, count := range entry.BySeverity {
			summary.BySeverity[severity] += count
		}
	}
	summary.Types = types
	return summary
}
