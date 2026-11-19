package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultParamsURL(t *testing.T) {
	tests := []struct {
		name   string
		params map[string]string
		want   string
	}{
		{"no parameters", nil, "https://api.acme.nullify.ai/scpm/dependencies/analyze"},
		{"one parameter", map[string]string{"githubOwnerId": "42"}, "https://api.acme.nullify.ai/scpm/dependencies/analyze?githubOwnerId=42"},
		{"encoded and sorted", map[string]string{"installationId": "a b", "azureOrganizationId": "org"}, "https://api.acme.nullify.ai/scpm/dependencies/analyze?azureOrganizationId=org&installationId=a+b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient("acme.nullify.ai", "token", tt.params)
			require.Equal(t, tt.want, client.DefaultParamsURL("/scpm/dependencies/analyze"))
		})
	}
}
