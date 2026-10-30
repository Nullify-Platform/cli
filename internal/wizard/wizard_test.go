package wizard

import (
	"context"
	"testing"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/stretchr/testify/require"
)

func TestRunSkipsCompletedSteps(t *testing.T) {
	executedSteps := []string{}

	steps := []Step{
		{
			Name:  "already done",
			Check: func(ctx context.Context) bool { return true },
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "already done")
				return nil
			},
		},
		{
			Name:  "needs work",
			Check: func(ctx context.Context) bool { return false },
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "needs work")
				return nil
			},
		},
	}

	err := Run(context.Background(), steps)
	require.NoError(t, err)
	require.Equal(t, []string{"needs work"}, executedSteps)
}

func TestRunNilCheckAlwaysExecutes(t *testing.T) {
	executed := false

	steps := []Step{
		{
			Name:  "no check",
			Check: nil,
			Execute: func(ctx context.Context) error {
				executed = true
				return nil
			},
		},
	}

	err := Run(context.Background(), steps)
	require.NoError(t, err)
	require.True(t, executed)
}

func TestRunStopsOnError(t *testing.T) {
	executedSteps := []string{}

	steps := []Step{
		{
			Name: "fails",
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "fails")
				return context.Canceled
			},
		},
		{
			Name: "should not run",
			Execute: func(ctx context.Context) error {
				executedSteps = append(executedSteps, "should not run")
				return nil
			},
		},
	}

	err := Run(context.Background(), steps)
	require.Error(t, err)
	require.Equal(t, []string{"fails"}, executedSteps)
}

func TestDomainFromInput(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "nullify.ai"},
		{"  \n", "nullify.ai"},
		{"acme\n", "api.acme.nullify.ai"},
		{"app.nullify.ai", "nullify.ai"},
		{"https://api.nullify.ai", "nullify.ai"},
	}
	for _, tt := range tests {
		got, err := domainFromInput(tt.input)
		require.NoError(t, err)
		require.Equal(t, tt.want, got, tt.input)
	}
}

func TestAuthStepCheckRequiresUsableSession(t *testing.T) {
	tests := []struct {
		name       string
		configHost string
		creds      map[string]auth.HostCredentials
		want       bool
	}{
		{
			name:       "tenant with token",
			configHost: "api.acme.nullify.ai",
			creds:      map[string]auth.HostCredentials{"acme.nullify.ai": {AccessToken: "t"}},
			want:       true,
		},
		{
			name:       "router with selected installation",
			configHost: "api.nullify.ai",
			creds:      map[string]auth.HostCredentials{"nullify.ai": {AccessToken: "t", DataHost: "acme.nullify.ai"}},
			want:       true,
		},
		{
			name:       "router without installation",
			configHost: "nullify.ai",
			creds:      map[string]auth.HostCredentials{"nullify.ai": {AccessToken: "t"}},
			want:       false,
		},
		{
			name:       "no credentials",
			configHost: "nullify.ai",
			want:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			require.NoError(t, auth.SaveConfig(&auth.Config{Host: tt.configHost}))
			for h, c := range tt.creds {
				require.NoError(t, auth.SaveHostCredentials(h, c))
			}

			require.Equal(t, tt.want, AuthStep().Check(context.Background()))
		})
	}
}
