package lib

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// BuildQueryString constructs a URL-encoded query string from a base map of
// parameters and optional key-value pairs. Extra pairs are specified as
// alternating key, value strings (e.g., "severity", "high", "status", "open").
// Empty values are skipped.
func BuildQueryString(base map[string]string, extra ...string) string {
	v := url.Values{}
	for k, val := range base {
		v.Set(k, val)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] != "" {
			v.Set(extra[i], extra[i+1])
		}
	}
	if len(v) == 0 {
		return ""
	}
	return "?" + v.Encode()
}

// Doer abstracts the Do method of http.Client, matching client.HTTPClient.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DoGet performs a GET request and returns the response body as a string.
// Returns an error if the request fails or the status code is not 2xx.
func DoGet(ctx context.Context, httpClient Doer, baseURL, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return string(body), nil
}
