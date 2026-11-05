package client

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/nullify-platform/cli/internal/logger"
)

type authTransport struct {
	nullifyHost string
	token       string
	transport   http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", "Nullify-CLI/"+logger.Version)
	if !bearerAllowed(t.nullifyHost, req) {
		r.Header.Del("Authorization")
		return t.transport.RoundTrip(r)
	}
	r.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(r)
}

// BearerAllowed reports whether req may carry the Nullify bearer for
// nullifyHost; see bearerAllowed.
func BearerAllowed(nullifyHost string, req *http.Request) bool {
	return bearerAllowed(nullifyHost, req)
}

// StripBearerOnRedirect is an http.Client CheckRedirect that follows a
// redirect without the Nullify bearer: the Location is the server's to choose
// and the user's token must not go wherever it points.
func StripBearerOnRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return http.ErrUseLastResponse
	}
	req.Header.Del("Authorization")
	return nil
}

// bearerAllowed reports whether req may carry the Nullify bearer: an https
// request to the API host the client was built for, made by the caller rather
// than by following a redirect. Anything else goes out without it, so a
// redirect, or a URL the server handed back, never receives the user's token.
func bearerAllowed(nullifyHost string, req *http.Request) bool {
	if req.Response != nil {
		return false
	}
	return isAPIOrigin(nullifyHost, req.URL)
}

func isAPIOrigin(nullifyHost string, u *url.URL) bool {
	if u == nil || u.Scheme != "https" || u.User != nil {
		return false
	}
	if port := u.Port(); port != "" && port != "443" {
		return false
	}
	apiHost := strings.ToLower(nullifyHost)
	if !strings.HasPrefix(apiHost, "api.") {
		apiHost = "api." + apiHost
	}
	return strings.ToLower(u.Hostname()) == apiHost
}
