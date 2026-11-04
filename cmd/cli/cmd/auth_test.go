package cmd

import (
	"testing"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestResolveLoginHost(t *testing.T) {
	tests := []struct {
		name       string
		flagHost   string
		configHost string
		want       string
		wantErr    bool
	}{
		{name: "defaults to the router", want: "nullify.ai"},
		{name: "configured tenant", configHost: "acme.nullify.ai", want: "acme.nullify.ai"},
		{name: "configured api tenant", configHost: "api.acme.nullify.ai", want: "acme.nullify.ai"},
		{name: "flag wins over config", flagHost: "beta.nullify.ai", configHost: "acme.nullify.ai", want: "beta.nullify.ai"},
		{name: "router alias flag", flagHost: "https://app.nullify.ai", configHost: "acme.nullify.ai", want: "nullify.ai"},
		{name: "api router alias", flagHost: "api.nullify.ai", want: "nullify.ai"},
		{name: "invalid flag", flagHost: "acme.example.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			resetCommandFlags(t)
			host = tt.flagHost
			if tt.configHost != "" {
				require.NoError(t, auth.SaveConfig(&auth.Config{Host: tt.configHost}))
			}

			got, err := resolveLoginHost()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
