package apierror

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type errorBody struct {
	Error string `json:"error"`
}

// APIError represents a structured error response from the Nullify API.
type APIError struct {
	StatusCode int
	Message    string
	Path       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("API error %d on %s: %s", e.StatusCode, e.Path, e.Message)
}

// IsNotFound returns true if the error is a 404 Not Found.
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// IsUnauthorized returns true if the error is a 401 Unauthorized.
func (e *APIError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized
}

// HandleError reads an HTTP error response and returns a structured *APIError.
func HandleError(resp *http.Response) error {
	path := ""
	if resp.Request != nil {
		path = resp.Request.URL.Path
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return &APIError{
			StatusCode: resp.StatusCode,
			Message:    fmt.Sprintf("failed to read error body: %v", err),
			Path:       path,
		}
	}

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		var errBody errorBody
		if json.Unmarshal(body, &errBody) == nil && errBody.Error != "" {
			return &APIError{
				StatusCode: resp.StatusCode,
				Message:    errBody.Error,
				Path:       path,
			}
		}
	}

	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    string(body),
		Path:       path,
	}
}
