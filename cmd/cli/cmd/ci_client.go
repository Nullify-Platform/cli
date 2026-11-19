package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/nullify-platform/cli/internal/apierror"
	"github.com/nullify-platform/cli/internal/client"
)

// maxFindingsResponseBytes bounds one finding list response. The bughunt
// route ignores the page size and returns up to 10000 findings at once, so
// the bound is well above the 10 MiB most commands use.
const maxFindingsResponseBytes = 64 << 20

// errFindingsResponseTooLarge reports a response cut off at the bound. It is
// an unreadable response, never a short list.
var errFindingsResponseTooLarge = fmt.Errorf(
	"%w: response is larger than %d bytes", errUnreadableFindings, maxFindingsResponseBytes,
)

// clientGetter sends finding list requests through the authenticated client.
// A response outside 2xx becomes an *apierror.APIError, so a caller can tell
// a refused request from any other failure.
func clientGetter(c *client.NullifyClient) findingsGetter {
	return func(ctx context.Context, path string) (string, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
		if err != nil {
			return "", err
		}
		resp, err := c.HttpClient.Do(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", apierror.HandleError(resp)
		}
		return readFindingsBody(resp.Body, maxFindingsResponseBytes)
	}
}

// readFindingsBody reads a response body of at most limit bytes. A longer
// body is an error rather than a truncated list.
func readFindingsBody(body io.Reader, limit int) (string, error) {
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		return "", err
	}
	if len(data) > limit {
		return "", errFindingsResponseTooLarge
	}
	return string(data), nil
}

// isAccessDenied reports a request the server refused with 401 or 403.
func isAccessDenied(err error) bool {
	var apiErr *apierror.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
}
