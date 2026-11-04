package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/nullify-platform/cli/internal/api/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsableInstallations(t *testing.T) {
	params := map[string]string{"githubOwnerId": "1"}
	outputs := []models.EndpointsAdminInstallationOutput{
		{Name: "ready", NullifyBaseURL: new("https://api.acme.nullify.ai"), QueryParameters: params},
		{Name: "pending", QueryParameters: params},
		{Name: "no-params", NullifyBaseURL: new("https://api.beta.nullify.ai")},
		{Name: "bad-url", NullifyBaseURL: new("https://api.acme.evil.com"), QueryParameters: params},
		{Name: "router-url", NullifyBaseURL: new("https://api.nullify.ai"), QueryParameters: params},
	}

	got := usableInstallations(context.Background(), outputs)

	require.Equal(t, []Installation{
		{Name: "ready", DataHost: "acme.nullify.ai", QueryParameters: params},
	}, got)

	got[0].QueryParameters["githubOwnerId"] = "2"
	require.Equal(t, "1", params["githubOwnerId"], "installation must not share the response map")
}

func TestInstallationPickerPick(t *testing.T) {
	acme := Installation{Name: "acme", DataHost: "acme.nullify.ai"}
	beta := Installation{Name: "beta", DataHost: "beta.nullify.ai"}
	acmeGitLab := Installation{Name: "acme", DataHost: "acme-gl.nullify.ai"}

	tests := []struct {
		name        string
		picker      InstallationPicker
		installs    []Installation
		want        Installation
		wantErr     string
		wantErrIs   error
		wantPrompts bool
	}{
		{name: "none", installs: nil, wantErrIs: errNoUsableInstallation},
		{name: "single selects automatically", installs: []Installation{acme}, want: acme},
		{name: "single still honours name", picker: InstallationPicker{Name: "beta"}, installs: []Installation{acme}, wantErr: `installation "beta" not found - available: acme`},
		{name: "by name", picker: InstallationPicker{Name: "beta"}, installs: []Installation{acme, beta}, want: beta},
		{name: "duplicate name", picker: InstallationPicker{Name: "acme"}, installs: []Installation{acme, acmeGitLab}, wantErr: "matches 2 installations"},
		{name: "many without terminal", installs: []Installation{acme, beta}, wantErr: "multiple installations are available (acme, beta) - pass --installation <name>"},
		{name: "prompt", picker: InstallationPicker{Interactive: true, In: strings.NewReader("2\n")}, installs: []Installation{acme, beta}, want: beta, wantPrompts: true},
		{name: "prompt without newline", picker: InstallationPicker{Interactive: true, In: strings.NewReader("1")}, installs: []Installation{acme, beta}, want: acme, wantPrompts: true},
		{name: "prompt out of range", picker: InstallationPicker{Interactive: true, In: strings.NewReader("3\n")}, installs: []Installation{acme, beta}, wantErr: "invalid selection", wantPrompts: true},
		{name: "prompt not a number", picker: InstallationPicker{Interactive: true, In: strings.NewReader("acme\n")}, installs: []Installation{acme, beta}, wantErr: "invalid selection", wantPrompts: true},
		{name: "prompt with duplicate names", picker: InstallationPicker{Interactive: true, In: strings.NewReader("1\n")}, installs: []Installation{acme, acmeGitLab}, wantErr: "used by more than one installation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			picker := tt.picker
			picker.Out = &out

			got, err := picker.Pick(tt.installs)

			switch {
			case tt.wantErrIs != nil:
				require.ErrorIs(t, err, tt.wantErrIs)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
			default:
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			}

			if tt.wantPrompts {
				require.Contains(t, out.String(), "1) acme (acme.nullify.ai)")
				require.Contains(t, out.String(), "2) beta (beta.nullify.ai)")
			} else {
				require.Empty(t, out.String())
			}
		})
	}
}

func TestFetchInstallationsSendsBearerToRouter(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/admin/installations", r.URL.Path)
		assert.Equal(t, "Bearer router-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"installations":[{"name":"acme","avatarUrl":"","provider":{},` +
			`"nullifyBaseUrl":"https://api.acme.nullify.ai","queryParameters":{"githubOwnerId":"7"}}]}`))
	})

	authHosts := recordAuthHosts(t)

	got, err := fetchInstallations(context.Background(), "router-token")
	require.NoError(t, err)
	requireOnlyRouterHost(t, *authHosts, 1)
	require.Equal(t, []Installation{
		{Name: "acme", DataHost: "acme.nullify.ai", QueryParameters: map[string]string{"githubOwnerId": "7"}},
	}, got)
}

func TestFetchInstallationsReportsServerError(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := fetchInstallations(context.Background(), "router-token")
	require.Error(t, err)
	require.False(t, errors.Is(err, errNoUsableInstallation))
}
