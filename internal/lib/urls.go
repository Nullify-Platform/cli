package lib

import (
	"errors"
	"net/url"
	"strings"
)

func SanitizeNullifyHost(nullifyHost string) (string, error) {
	if strings.Contains(nullifyHost, "://") {
		nullifyHost = strings.Split(nullifyHost, "://")[1]
	}

	nullifyURL, err := url.Parse("https://" + nullifyHost)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(nullifyURL.Host, "api.") || !strings.HasSuffix(nullifyURL.Host, ".nullify.ai") {
		return "", errors.New("invalid host, must be in the format api.<your-instance>.nullify.ai")
	}

	return nullifyURL.Host, nil
}
