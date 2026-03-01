package lib

import (
	"errors"
	"net/url"
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
		return "api." + input + ".nullify.ai", nil
	}

	return "", errors.New("invalid domain format: expected 'customer', 'customer.nullify.ai', or 'api.customer.nullify.ai'")
}

func SanitizeNullifyHost(nullifyHost string) (string, error) {
	if strings.Contains(nullifyHost, "://") {
		nullifyHost = strings.Split(nullifyHost, "://")[1]
	}

	nullifyURL, err := url.Parse("https://" + nullifyHost)
	if err != nil {
		return "", err
	}

	if !strings.HasSuffix(nullifyURL.Host, ".nullify.ai") {
		return "", errors.New("invalid host, must be in the format <your-instance>.nullify.ai")
	}

	return nullifyURL.Host, nil
}
