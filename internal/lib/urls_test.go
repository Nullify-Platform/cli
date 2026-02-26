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
			expectedHost: "api.example.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "input host with scheme, path and query params",
			inputHost:    "https://api.example.nullify.ai/path?query=param",
			expectedHost: "api.example.nullify.ai",
			wantErr:      false,
		},
		{
			name:         "input host with invalid scheme",
			inputHost:    "random://api.example.nullify.ai",
			expectedHost: "api.example.nullify.ai",
			wantErr:      false,
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
