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
	r := req.Clone(req.Context())
	r.URL.Scheme = "https"
	r.URL.Host = t.nullifyHost
	r.Host = t.nullifyHost
	r.Header.Set("Authorization", "Bearer "+t.token)
	r.Header.Set("User-Agent", "Nullify-CLI/"+logger.Version)
	return t.transport.RoundTrip(r)
}
