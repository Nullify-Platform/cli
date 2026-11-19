package client

import (
	"net/http"
	"strings"
	"time"
)

// HTTPClient defines the interface for making HTTP requests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// NullifyClient wraps an HTTP client configured for the Nullify API.
type NullifyClient struct {
	Host       string
	BaseURL    string
	Token      string
	HttpClient HTTPClient
}

// NewNullifyClient creates a client for the given host with bearer token auth.
func NewNullifyClient(nullifyHost string, token string) *NullifyClient {
	apiHost := nullifyHost
	if !strings.HasPrefix(nullifyHost, "api.") {
		apiHost = "api." + nullifyHost
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: NewRetryTransport(&authTransport{
			nullifyHost: nullifyHost,
			token:       token,
			transport:   http.DefaultTransport,
		}),
	}

	return &NullifyClient{
		Host:       nullifyHost,
		BaseURL:    "https://" + apiHost,
		Token:      token,
		HttpClient: httpClient,
	}
}
