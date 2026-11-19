package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// pagedGetter serves one body per nextToken value and records each request.
func pagedGetter(pages map[string]string, requests *[]string) findingsGetter {
	return func(_ context.Context, path string) (string, error) {
		*requests = append(*requests, path)
		parsed, err := url.Parse(path)
		if err != nil {
			return "", err
		}
		body, ok := pages[parsed.Query().Get("nextToken")]
		if !ok {
			return "", errors.New("unexpected page")
		}
		return body, nil
	}
}

func TestVisitFindingPages(t *testing.T) {
	endless := map[string]string{
		"":     `{"findings":[{"id":"f1"}],"numItems":1,"nextToken":"next"}`,
		"next": `{"findings":[{"id":"f2"}],"numItems":1,"nextToken":"next"}`,
	}
	tests := []struct {
		name         string
		pages        map[string]string
		stopAfter    int
		wantRequests []string
		wantFindings int
		wantErr      error
	}{
		{
			name:         "one page",
			pages:        map[string]string{"": `{"findings":[{"id":"f1"}],"numItems":1,"nextToken":""}`},
			wantRequests: []string{"/sast/findings?limit=100"},
			wantFindings: 1,
		},
		{
			name: "follows nextToken to the last page",
			pages: map[string]string{
				"":   `{"findings":[{"id":"f1"},{"id":"f2"}],"numItems":2,"nextToken":"p2"}`,
				"p2": `{"findings":[{"id":"f3"}],"numItems":1,"nextToken":"p3"}`,
				"p3": `{"findings":[],"numItems":0}`,
			},
			wantRequests: []string{
				"/sast/findings?limit=100",
				"/sast/findings?limit=100&nextToken=p2",
				"/sast/findings?limit=100&nextToken=p3",
			},
			wantFindings: 3,
		},
		{
			name:         "a null nextToken ends the list",
			pages:        map[string]string{"": `{"findings":[{"id":"f1"}],"nextToken":null}`},
			wantRequests: []string{"/sast/findings?limit=100"},
			wantFindings: 1,
		},
		{
			name:         "the visitor can stop early",
			pages:        endless,
			stopAfter:    1,
			wantRequests: []string{"/sast/findings?limit=100"},
			wantFindings: 1,
		},
		{
			name:         "an endless list fails rather than looping",
			pages:        endless,
			wantFindings: maxFindingPages,
			wantErr:      errTooManyFindingPages,
		},
		{
			name:         "an unreadable page fails",
			pages:        map[string]string{"": `{"total":3}`},
			wantRequests: []string{"/sast/findings?limit=100"},
			wantErr:      errUnreadableFindings,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests []string
			seen := 0
			err := visitFindingPages(
				context.Background(),
				pagedGetter(tt.pages, &requests),
				"/sast/findings",
				nil,
				nil,
				func(findings []json.RawMessage) bool {
					seen += len(findings)
					return tt.stopAfter == 0 || seen < tt.stopAfter
				},
			)

			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantFindings, seen)
			if tt.wantRequests != nil {
				require.Equal(t, tt.wantRequests, requests)
			}
		})
	}
}

func TestVisitFindingPagesKeepsTheBaseQuery(t *testing.T) {
	var requests []string
	pages := map[string]string{"": `{"findings":[],"numItems":0}`}

	err := visitFindingPages(
		context.Background(),
		pagedGetter(pages, &requests),
		"/secrets/findings",
		map[string]string{"githubOwnerId": "42"},
		[]string{"isResolved", "false"},
		func([]json.RawMessage) bool { return true },
	)

	require.NoError(t, err)
	require.Equal(t, []string{"/secrets/findings?githubOwnerId=42&isResolved=false&limit=100"}, requests)
}

func TestDecodeFindingsPage(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		findings  int
		nextToken string
	}{
		{"sast envelope", `{"version":"1","findings":[{"id":"f1"}],"numItems":1,"nextToken":""}`, 1, ""},
		{"sca dependencies envelope", `{"version":"1","findings":[{"id":"f1"},{"id":"f2"}],"numItems":2,"nextToken":"abc"}`, 2, "abc"},
		{"sca containers envelope", `{"findings":[{"id":"f1"}],"numItems":1,"nextToken":""}`, 1, ""},
		{"secrets envelope", `{"findings":[],"numItems":0,"nextToken":""}`, 0, ""},
		{"pentest envelope", `{"findings":[{"id":"f1"},{"id":"f2"},{"id":"f3"}],"numItems":0,"nextToken":""}`, 3, ""},
		{"bughunt envelope omits numItems", `{"findings":[{"id":"f1"},{"id":"f2"}]}`, 2, ""},
		{"cspm envelope omits empty nextToken", `{"findings":[{"id":"f1"}],"numItems":1,"version":"1"}`, 1, ""},
		{"cspm envelope with a nextToken", `{"findings":[{"id":"f1"}],"numItems":1,"nextToken":"100"}`, 1, "100"},
		{"nil findings slice serialises as null", `{"findings":null,"numItems":0,"nextToken":""}`, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := decodeFindingsPage(tt.body)
			require.NoError(t, err)
			require.Len(t, page.findings, tt.findings)
			require.Equal(t, tt.nextToken, page.nextToken)
		})
	}
}

func TestDecodeFindingsPageRejectsUnknownEnvelopes(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "invalid json", body: `not json`},
		{name: "empty object", body: `{}`},
		{name: "bare array", body: `[{"id":"f1"}]`},
		{name: "items envelope", body: `{"items":[{"id":"f1"}]}`},
		{name: "total envelope", body: `{"total":42}`},
		{name: "findings is not an array", body: `{"findings":{"id":"f1"}}`},
		{name: "empty body", body: ``},
		{name: "object with zero count", body: `{"findings":{},"numItems":0}`},
		{name: "boolean with zero count", body: `{"findings":false,"numItems":0}`},
		{name: "negative count", body: `{"findings":[],"numItems":-1}`},
		{name: "understated positive count", body: `{"findings":[{"id":"f1"},{"id":"f2"}],"numItems":1}`},
		{name: "overstated count", body: `{"findings":[],"numItems":1}`},
		{name: "nextToken is not a string", body: `{"findings":[],"nextToken":7}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := decodeFindingsPage(tt.body)
			require.ErrorIs(t, err, errUnreadableFindings)
			require.Empty(t, page.findings)
		})
	}
}
