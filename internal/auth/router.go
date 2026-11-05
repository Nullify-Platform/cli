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

// Router is one Nullify router environment. Key is where its login is stored
// and the host commands name it by; AuthHost serves sign-in and the org list;
// a data host it lists must be api.<label>.<dataDomain>, and any other is
// never contacted.
type Router struct {
	Key        string
	AuthHost   string
	AppURL     string
	dataDomain string
}

var routers = []Router{
	{Key: RouterHost, AuthHost: "api.nullify.ai", AppURL: RouterAppURL, dataDomain: "nullify.ai"},
	{Key: "router.dev.nullify.ai", AuthHost: "api.router.dev.nullify.ai", AppURL: "https://app.router.dev.nullify.ai", dataDomain: "dev.nullify.ai"},
}

// ErrNoDataHost reports that the router credentials have no selected installation.
var ErrNoDataHost = errors.New("no organization selected for the router sign-in - run 'nullify auth login'")

// RouterFor returns the router environment host names in its bare, "api." or
// "app." form.
func RouterFor(host string) (Router, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+len("://"):]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimPrefix(strings.TrimPrefix(h, "api."), "app.")
	for _, r := range routers {
		if h == r.Key {
			return r, true
		}
	}
	return Router{}, false
}

func normalizeHost(host string) string {
	if r, ok := RouterFor(host); ok {
		return r.Key
	}
	return host
}

// IsRouterHost reports whether host is a bare, "api." or "app." form of a router host.
func IsRouterHost(host string) bool {
	_, ok := RouterFor(host)
	return ok
}

// dataHostFromBaseURL returns the bare tenant host of a plain https tenant API origin on the production router.
func dataHostFromBaseURL(baseURL string) (string, error) {
	return routers[0].dataHost(baseURL)
}

// dataHost returns the bare tenant host of baseURL when it is a plain https
// origin of this router's tenants.
func (r Router) dataHost(baseURL string) (string, error) {
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
	if port := u.Port(); port != "" && port != "443" {
		return "", fmt.Errorf("base URL %q must not name a port other than 443", baseURL)
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("base URL %q must not contain a path", baseURL)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("base URL %q must not contain a query or fragment", baseURL)
	}

	tenant, ok := r.tenantLabel(strings.ToLower(u.Hostname()))
	if !ok {
		return "", fmt.Errorf("base URL %q is not a tenant API host of %s", baseURL, r.Key)
	}
	return tenant + "." + r.dataDomain, nil
}

// tenantLabel returns <tenant> from a host of the form "api.<tenant>.<dataDomain>".
func (r Router) tenantLabel(hostname string) (string, bool) {
	rest, ok := strings.CutPrefix(hostname, "api.")
	if !ok {
		return "", false
	}
	label, ok := strings.CutSuffix(rest, "."+r.dataDomain)
	if !ok || !validTenantLabel(label) || label+"."+r.dataDomain == r.Key {
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
