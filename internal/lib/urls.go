package lib

import (
	"errors"
	"strings"
)

// ParseCustomerDomain accepts various forms of customer input and returns
// the canonical API host. Accepted formats:
//   - "acme" → "api.acme.nullify.ai"
//   - "acme.nullify.ai" → "api.acme.nullify.ai"
//   - "api.acme.nullify.ai" → "api.acme.nullify.ai"
func ParseCustomerDomain(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("customer domain cannot be empty")
	}

	// Strip any scheme
	if strings.Contains(input, "://") {
		input = strings.Split(input, "://")[1]
	}

	// Strip path and query parameters
	if idx := strings.IndexAny(input, "/?"); idx != -1 {
		input = input[:idx]
	}

	// Already a full API host
	if strings.HasPrefix(input, "api.") && strings.HasSuffix(input, ".nullify.ai") {
		return input, nil
	}

	// Has .nullify.ai suffix but no api. prefix
	if strings.HasSuffix(input, ".nullify.ai") {
		return "api." + input, nil
	}

	// Just the customer name (no dots or only internal dots)
	if !strings.Contains(input, ".") {
		// Reject names with invalid hostname characters
		if strings.ContainsAny(input, ":@!#$%^&*()+=[]{}|\\<>,") {
			return "", errors.New("invalid domain format: contains invalid characters")
		}
		return "api." + input + ".nullify.ai", nil
	}

	return "", errors.New("invalid domain format: expected 'customer', 'customer.nullify.ai', or 'api.customer.nullify.ai'")
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
