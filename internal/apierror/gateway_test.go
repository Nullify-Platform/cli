package apierror

import (
	"net/http"
	"testing"
)

func TestIsGatewayForbidden(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		want   bool
	}{
		{name: "authorizer deny", status: http.StatusForbidden, body: `{"message":"Forbidden"}`, want: true},
		{name: "authorizer deny with newline", status: http.StatusForbidden, body: "{\"message\":\"Forbidden\"}\n", want: true},
		{name: "handler permission error", status: http.StatusForbidden, body: `{"error":"missing permission finding:write"}`},
		{name: "other message", status: http.StatusForbidden, body: `{"message":"not hosted on this instance"}`},
		{name: "extra fields", status: http.StatusForbidden, body: `{"message":"Forbidden","code":"x"}`},
		{name: "not json", status: http.StatusForbidden, body: `Forbidden`},
		{name: "401", status: http.StatusUnauthorized, body: `{"message":"Forbidden"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsGatewayForbidden(tt.status, []byte(tt.body)); got != tt.want {
				t.Errorf("IsGatewayForbidden(%d, %q) = %v, want %v", tt.status, tt.body, got, tt.want)
			}
		})
	}
}
