package client

import (
	"net/http"
	"os"
)

type authTransport struct {
	transport http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+os.Getenv("NULLIFY_TOKEN"))
	return t.transport.RoundTrip(req)
}

func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &authTransport{
			transport: http.DefaultTransport,
		},
	}
}
