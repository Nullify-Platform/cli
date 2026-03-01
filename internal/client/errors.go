package client

import (
	"net/http"

	"github.com/nullify-platform/cli/internal/apierror"
)

// APIError is an alias for apierror.APIError for backwards compatibility.
type APIError = apierror.APIError

// HandleError reads an HTTP error response and returns a structured *APIError.
func HandleError(resp *http.Response) error {
	return apierror.HandleError(resp)
}
