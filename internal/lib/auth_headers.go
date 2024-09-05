package lib

import (
	"context"
	"fmt"
	"strings"

	"github.com/nullify-platform/logger/pkg/logger"
)

func ParseAuthHeaders(ctx context.Context, authHeaders []string) (map[string]string, error) {
	result := map[string]string{}

	for _, header := range authHeaders {
		headers := strings.Split(header, ",")
		for _, h := range headers {
			headerParts := strings.Split(h, ": ")
			if len(headerParts) != 2 {
				logger.L(ctx).Error("please provide headers in the format of 'key: value'")
				err := fmt.Errorf("please provide headers in the format of 'key: value'")
				return nil, err
			}

			headerName := strings.TrimSpace(headerParts[0])
			headerValue := strings.TrimSpace(headerParts[1])
			result[headerName] = headerValue
		}
	}

	return result, nil
}
