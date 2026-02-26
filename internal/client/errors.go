package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

func HandleError(resp *http.Response) error {
	if resp.Header.Get("Content-Type") != "application/json" {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf(
				"unexpected status code %d (non-JSON response)",
				resp.StatusCode,
			)
		}

		return fmt.Errorf(
			"unexpected status code %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	body := errorBody{}
	err := json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return err
	}

	return fmt.Errorf(
		"unexpected status code %d: %s",
		resp.StatusCode,
		body.Error,
	)
}
