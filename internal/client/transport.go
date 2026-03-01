package client

import (
	"net/http"

	"github.com/nullify-platform/logger/pkg/logger"
)

type authTransport struct {
	nullifyHost string
	token       string
	transport   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "https"
	req.URL.Host = t.nullifyHost
	req.Host = t.nullifyHost
	req.Header.Set("Authorization", "Bearer "+t.token)
	req.Header.Set("User-Agent", "Nullify-CLI/"+logger.Version)
	return t.transport.RoundTrip(req)
}
