package auth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// RouterHost is the bare host of the Nullify router, which serves sign-in but not tenant data.
const RouterHost = "nullify.ai"

// RouterAppURL is the dashboard URL for users who sign in through the router.
const RouterAppURL = "https://app.nullify.ai"

var routerAliases = map[string]bool{
	"nullify.ai":     true,
	"api.nullify.ai": true,
	"app.nullify.ai": true,
}

// ErrNoDataHost reports that the router credentials have no selected installation.
var ErrNoDataHost = errors.New("no installation selected for nullify.ai - run 'nullify auth login' or 'nullify auth switch --installation <name>'")

func normalizeHost(host string) string {
	if IsRouterHost(host) {
		return RouterHost
	}
	return host
}

// IsRouterHost reports whether host is a bare, "api." or "app." form of the router host.
func IsRouterHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+len("://"):]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	return routerAliases[h]
}

// dataHostFromBaseURL returns the bare tenant host of a plain https tenant API origin.
func dataHostFromBaseURL(baseURL string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse base URL %q: %w", baseURL, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("base URL %q is not https", baseURL)
	}
	if u.User != nil {
		return "", fmt.Errorf("base URL %q must not contain userinfo", baseURL)
	}
	if u.Port() != "" {
		return "", fmt.Errorf("base URL %q must not contain a port", baseURL)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("base URL %q must not contain a path", baseURL)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("base URL %q must not contain a query or fragment", baseURL)
	}

	tenant, ok := tenantLabel(u.Hostname())
	if !ok {
		return "", fmt.Errorf("base URL %q is not a Nullify tenant API host", baseURL)
	}
	return tenant + "." + RouterHost, nil
}

// tenantLabel returns <tenant> from a host of the form "api.<tenant>.nullify.ai".
func tenantLabel(hostname string) (string, bool) {
	rest, ok := strings.CutPrefix(hostname, "api.")
	if !ok {
		return "", false
	}
	label, ok := strings.CutSuffix(rest, "."+RouterHost)
	if !ok || !validTenantLabel(label) {
		return "", false
	}
	return label, true
}

func validTenantLabel(label string) bool {
	if label == "" || len(label) > 63 || label == "api" || label == "app" {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
