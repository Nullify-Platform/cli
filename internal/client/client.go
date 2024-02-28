package client

import (
	"net/http"

	"github.com/nullify-platform/logger/pkg/logger"
)

type authTransport struct {
	token     string
	transport http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}

func NewHTTPClient(nullifyHost string, token string) (*http.Client, error) {

	logger.Debug(
		"using token",
		logger.String("token", token),
	)

	return &http.Client{
		Transport: &authTransport{
			token:     token,
			transport: http.DefaultTransport,
		},
	}, nil
}
