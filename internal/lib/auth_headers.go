package lib

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/nullify-platform/cli/internal/logger"
)

var multiHeaderPattern = regexp.MustCompile(`, [A-Z][a-zA-Z0-9-]+: `)

func ParseAuthHeaders(ctx context.Context, authHeaders []string) (map[string]string, error) {
	result := map[string]string{}

	for _, header := range authHeaders {
		headerParts := strings.SplitN(header, ":", 2)
		if len(headerParts) != 2 {
			logger.L(ctx).Error("please provide one header per flag in the format 'key: value'")
			return nil, fmt.Errorf("please provide one header per flag in the format 'key: value'")
		}

		headerName := strings.TrimSpace(headerParts[0])
		headerValue := strings.TrimSpace(headerParts[1])
		if headerName == "" {
			logger.L(ctx).Error("header name cannot be empty")
			return nil, fmt.Errorf("header name cannot be empty")
		}

		result[headerName] = headerValue

		// Warn if the value looks like it contains another header.
		if multiHeaderPattern.MatchString(headerValue) {
			logger.L(ctx).Warn("header value looks like it may contain multiple headers; use repeated --header flags instead",
				logger.String("header", headerName),
			)
		}
	}

	return result, nil
}
