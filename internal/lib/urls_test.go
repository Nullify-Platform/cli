package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCustomerDomain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "just customer name",
			input: "acme",
			want:  "api.acme.nullify.ai",
		},
		{
			name:  "customer.nullify.ai",
			input: "acme.nullify.ai",
			want:  "api.acme.nullify.ai",
		},
		{
			name:  "full api host",
			input: "api.acme.nullify.ai",
			want:  "api.acme.nullify.ai",
		},
		{
			name:  "with https scheme",
			input: "https://api.acme.nullify.ai",
			want:  "api.acme.nullify.ai",
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid domain with dots",
			input:   "acme.example.com",
			wantErr: true,
		},
		{
			name:  "router bare host",
			input: "nullify.ai",
			want:  "api.nullify.ai",
		},
		{
			name:  "router app host",
			input: "app.nullify.ai",
			want:  "api.nullify.ai",
		},
		{
			name:  "router api host",
			input: "api.nullify.ai",
			want:  "api.nullify.ai",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCustomerDomain(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSanitizeNullifyHost(t *testing.T) {
	tests := []struct {
		name         string
		inputHost    string
		expectedHost string
		wantErr      bool
	}{
		{
			name:         "valid input host",
			inputHost:    "api.example.nullify.ai",
			expectedHost: "example.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "input host with scheme, path and query params",
			inputHost:    "https://api.example.nullify.ai/path?query=param",
			expectedHost: "example.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "input host with invalid scheme",
			inputHost:    "random://api.example.nullify.ai",
			expectedHost: "example.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "bare host without api prefix",
			inputHost:    "acme.nullify.ai",
			expectedHost: "acme.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "bare host with scheme",
			inputHost:    "https://acme.nullify.ai",
			expectedHost: "acme.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "router bare host",
			inputHost:    "nullify.ai",
			expectedHost: "nullify.ai",
		},
		{
			name:         "router api host",
			inputHost:    "api.nullify.ai",
			expectedHost: "nullify.ai",
		},
		{
			name:         "router app host with scheme and path",
			inputHost:    "https://app.nullify.ai/dashboard?tab=1",
			expectedHost: "nullify.ai",
		},
		{
			name:         "router host in upper case",
			inputHost:    "HTTPS://API.NULLIFY.AI",
			expectedHost: "nullify.ai",
		},
		{
			name:         "tenant host is not the router",
			inputHost:    "app.acme.nullify.ai",
			expectedHost: "app.acme.nullify.ai",
		},
		{
			name:         "input host with invalid scheme delimiter",
			inputHost:    "random:/|api.example.nullify.ai",
			expectedHost: "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualHost, err := SanitizeNullifyHost(tt.inputHost)
			require.Equal(t, tt.wantErr, err != nil, tt.name)
			require.Equal(t, tt.expectedHost, actualHost, tt.name)
		})
	}
}
