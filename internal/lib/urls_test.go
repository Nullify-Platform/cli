package lib

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
