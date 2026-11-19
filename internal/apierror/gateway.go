package apierror

import (
	"bytes"
	"encoding/json"
	"net/http"
)

// gatewayForbiddenMessage is the body API Gateway sends when the tenant
// authorizer denies a request. The authorizer denies an expired, revoked or
// malformed token this way, with 403 rather than 401.
const gatewayForbiddenMessage = "Forbidden"

// IsGatewayForbidden reports whether status and body are API Gateway's own
// 403 for a token the authorizer rejected: exactly {"message":"Forbidden"}.
// A handler's 403, such as a missing permission, has another body and is
// not a token problem, so a refresh would not help.
func IsGatewayForbidden(status int, body []byte) bool {
	if status != http.StatusForbidden {
		return false
	}
	var out map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(body), &out); err != nil || len(out) != 1 {
		return false
	}
	msg, ok := out["message"].(string)
	return ok && msg == gatewayForbiddenMessage
}
