package lib

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
)

// ParseCustomerDomain accepts various forms of customer input and returns
// the canonical API host. Accepted formats:
//   - "acme" → "api.acme.nullify.ai"
//   - "acme.nullify.ai" → "api.acme.nullify.ai"
//   - "api.acme.nullify.ai" → "api.acme.nullify.ai"
//   - "nullify.ai", "app.nullify.ai" or "api.nullify.ai" → "api.nullify.ai"
//     (and likewise for the dev router, router.dev.nullify.ai)
func ParseCustomerDomain(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("customer domain cannot be empty")
	}

	hostname, err := parseHostname(input)
	if err != nil {
		return "", err
	}

	if router, ok := auth.RouterFor(hostname); ok {
		return router.AuthHost, nil
	}

	// Already a full API host
	if strings.HasPrefix(hostname, "api.") && strings.HasSuffix(hostname, ".nullify.ai") {
		return hostname, nil
	}

	// Has .nullify.ai suffix but no api. prefix
	if strings.HasSuffix(hostname, ".nullify.ai") {
		return "api." + hostname, nil
	}

	// Just the customer name
	if !strings.Contains(hostname, ".") {
		return "api." + hostname + ".nullify.ai", nil
	}

	return "", errors.New("invalid domain format: expected 'customer', 'customer.nullify.ai', or 'api.customer.nullify.ai'")
}

// parseHostname reads input as a URL authority, with or without a scheme
// (which is ignored: requests always use https), and returns its lower-case
// host name. A path or query is dropped, as from a
// pasted dashboard URL; userinfo, a port, a fragment or an invalid DNS label
// is an error, so the host checked is the host a request would reach.
func parseHostname(input string) (string, error) {
	raw := input
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid domain format: %w", err)
	}
	if u.User != nil {
		return "", errors.New("invalid domain format: must not contain userinfo")
	}
	if strings.Contains(u.Host, ":") {
		return "", errors.New("invalid domain format: must not contain a port")
	}
	if u.Fragment != "" || strings.Contains(input, "#") {
		return "", errors.New("invalid domain format: must not contain a fragment")
	}

	hostname := strings.ToLower(u.Hostname())
	if hostname == "" || len(hostname) > 253 {
		return "", errors.New("invalid domain format: no host name")
	}
	for _, label := range strings.Split(hostname, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid domain format: %q is not a valid host name", hostname)
		}
	}
	return hostname, nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// SanitizeNullifyHost cleans a host string (strips scheme, path, query) and
// validates it belongs to the nullify.ai domain. Unlike ParseCustomerDomain,
// it preserves the bare form (e.g. "acme.nullify.ai") without adding "api.".
func SanitizeNullifyHost(nullifyHost string) (string, error) {
	apiHost, err := ParseCustomerDomain(nullifyHost)
	if err != nil {
		return "", err
	}
	// Return the bare host form — callers add "api." when needed.
	return strings.TrimPrefix(apiHost, "api."), nil
}
