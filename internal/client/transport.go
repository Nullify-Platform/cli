package client

import "net/http"

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
	return t.transport.RoundTrip(req)
}
