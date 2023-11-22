package lib

import (
	"fmt"
	"strings"

	"github.com/nullify-platform/logger/pkg/logger"
)

func ParseAuthHeaders(authHeaders []string) (map[string]string, error) {
	result := map[string]string{}

	for _, header := range authHeaders {
		headerParts := strings.Split(header, ": ")
		if len(headerParts) != 2 {
			err := fmt.Errorf("please provide headers in the format of 'key: value'")
			logger.Err(err)
			return nil, err
		}

		headerName := strings.TrimSpace(headerParts[0])
		headerValue := strings.TrimSpace(headerParts[1])
		result[headerName] = headerValue
	}

	return result, nil
}
