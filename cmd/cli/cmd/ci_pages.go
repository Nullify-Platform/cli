package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	"github.com/nullify-platform/cli/internal/lib"
)

// findingsPageSize is the largest page the scanner list routes accept. The
// SAST, SCA and secrets routes reject a larger limit with InvalidArgument and
// the CSPM route clamps to it, so asking for more fails or truncates.
const findingsPageSize = 100

// maxFindingPages bounds how many pages one finding list may take. A list
// that is still going after this many pages is reported as an error rather
// than as a partial result, because a gate that stopped reading cannot
// confirm that the rest of the list is clean.
const maxFindingPages = 100

// errUnreadableFindings reports a findings response that does not carry the
// scanner envelope. It is never reported as a count of zero: a gate that cannot
// read the response must block the build rather than declare the repo clean.
var errUnreadableFindings = errors.New("unrecognised findings response envelope")

// errTooManyFindingPages reports a finding list that did not end within
// maxFindingPages pages.
var errTooManyFindingPages = fmt.Errorf(
	"the finding list did not end within %d pages of %d findings",
	maxFindingPages, findingsPageSize,
)

// findingsGetter sends a GET for a path with its query string and returns
// the response body.
type findingsGetter func(ctx context.Context, path string) (string, error)

// findingsPage is one decoded page of a scanner list route.
type findingsPage struct {
	findings  []json.RawMessage
	nextToken string
}

// visitFindingPages reads a finding list page by page at the page cap and
// passes each page's findings to visit. It follows nextToken until the server
// returns none, or until visit returns false.
func visitFindingPages(
	ctx context.Context,
	get findingsGetter,
	path string,
	base map[string]string,
	params []string,
	visit func([]json.RawMessage) bool,
) error {
	token := ""
	for range maxFindingPages {
		pageParams := append(
			append([]string{}, params...),
			"limit", strconv.Itoa(findingsPageSize),
			"nextToken", token,
		)
		body, err := get(ctx, path+lib.BuildQueryString(base, pageParams...))
		if err != nil {
			return err
		}
		page, err := decodeFindingsPage(body)
		if err != nil {
			return err
		}
		if !visit(page.findings) || page.nextToken == "" {
			return nil
		}
		token = page.nextToken
	}
	return errTooManyFindingPages
}

// collectFindings returns every finding of a list, reading all of its pages.
func collectFindings(
	ctx context.Context,
	get findingsGetter,
	path string,
	base map[string]string,
	params []string,
) ([]json.RawMessage, error) {
	var all []json.RawMessage
	err := visitFindingPages(ctx, get, path, base, params, func(page []json.RawMessage) bool {
		all = append(all, page...)
		return true
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

// decodeFindingsPage reads one page of a scanner list route. The page must
// carry a findings array, and a numItems that is present and non-zero must
// match its length.
func decodeFindingsPage(body string) (findingsPage, error) {
	var envelope struct {
		Findings  json.RawMessage `json:"findings"`
		NumItems  *int            `json:"numItems"`
		NextToken *string         `json:"nextToken"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return findingsPage{}, fmt.Errorf("%w: %w", errUnreadableFindings, err)
	}
	if len(envelope.Findings) == 0 {
		return findingsPage{}, fmt.Errorf("%w: no \"findings\" field", errUnreadableFindings)
	}

	var findings []json.RawMessage
	if err := json.Unmarshal(envelope.Findings, &findings); err != nil {
		return findingsPage{}, fmt.Errorf("%w: \"findings\" is not an array: %w", errUnreadableFindings, err)
	}
	if envelope.NumItems != nil && *envelope.NumItems != 0 && *envelope.NumItems != len(findings) {
		return findingsPage{}, fmt.Errorf(
			"%w: numItems %d does not match findings length %d",
			errUnreadableFindings, *envelope.NumItems, len(findings),
		)
	}

	page := findingsPage{findings: findings}
	if envelope.NextToken != nil {
		page.nextToken = *envelope.NextToken
	}
	return page, nil
}
