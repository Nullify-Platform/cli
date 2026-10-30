package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func installationsBody(entries ...string) string {
	return `{"installations":[` + strings.Join(entries, ",") + `]}`
}

func entry(name, baseURL, id string) string {
	if baseURL == "" {
		return fmt.Sprintf(`{"name":%q,"provider":{},"queryParameters":{"githubOwnerId":%q}}`, name, id)
	}
	return fmt.Sprintf(`{"name":%q,"provider":{},"nullifyBaseUrl":%q,"queryParameters":{"githubOwnerId":%q}}`, name, baseURL, id)
}

// A router's org is used only from one of that router's own tenant origins:
// a listing naming any other host, the other router environment's tenants
// included, leaves the org unavailable and the host is never contacted.
func TestRoutedOrgsKeepOnlyTheRoutersTenantOrigins(t *testing.T) {
	body := installationsBody(
		entry("ready", "https://api.acme.nullify.ai", "1"),
		entry("pending", "", "2"),
		entry("evil", "https://api.acme.evil.com", "3"),
		entry("fragment", "https://api.attacker.example#.nullify.ai", "4"),
		entry("router", "https://api.nullify.ai", "5"),
		entry("dev", "https://api.sandbox.dev.nullify.ai", "6"),
		entry("port", "https://api.acme.nullify.ai:8443", "7"),
	)
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })

	prod, err := fetchOrgs(context.Background(), "api.nullify.ai", "router-token")
	require.NoError(t, err)
	routed := routedOrgs(prod)
	require.Len(t, routed, 1)
	require.Equal(t, "ready", routed[0].Name)
	require.Equal(t, "acme.nullify.ai", routed[0].DataHost())
	require.Equal(t, map[string]string{"githubOwnerId": "1"}, routed[0].Query())

	dev, err := fetchOrgs(context.Background(), "api.router.dev.nullify.ai", "router-token")
	require.NoError(t, err)
	routed = routedOrgs(dev)
	require.Len(t, routed, 1)
	require.Equal(t, "dev", routed[0].Name)
	require.Equal(t, "sandbox.dev.nullify.ai", routed[0].DataHost())
}

func TestInstallationPickerPick(t *testing.T) {
	acme := Org{Name: "acme", Key: "githubOwnerId", ID: "1", Host: "api.acme.nullify.ai"}
	beta := Org{Name: "beta", Key: "githubOwnerId", ID: "2", Host: "api.beta.nullify.ai"}
	acmeElsewhere := Org{Name: "acme", Key: "githubOwnerId", ID: "3", Host: "api.acme-gl.nullify.ai"}

	tests := []struct {
		name        string
		picker      InstallationPicker
		orgs        []Org
		want        Org
		wantErr     string
		wantErrIs   error
		wantPrompts bool
	}{
		{name: "none", orgs: nil, wantErrIs: errNoUsableInstallation},
		{name: "single selects automatically", orgs: []Org{acme}, want: acme},
		{name: "single still honours name", picker: InstallationPicker{Name: "beta"}, orgs: []Org{acme}, wantErr: `organization "beta" not found - available: acme`},
		{name: "by name", picker: InstallationPicker{Name: "beta"}, orgs: []Org{acme, beta}, want: beta},
		{name: "by id", picker: InstallationPicker{Name: "2"}, orgs: []Org{acme, beta}, want: beta},
		{name: "duplicate name", picker: InstallationPicker{Name: "acme"}, orgs: []Org{acme, acmeElsewhere}, wantErr: "matches 2 organizations"},
		{name: "remembered", picker: InstallationPicker{Remembered: &OrgPick{Key: "githubOwnerId", ID: "2"}}, orgs: []Org{acme, beta}, want: beta},
		{name: "remembered but gone", picker: InstallationPicker{Remembered: &OrgPick{Key: "githubOwnerId", ID: "9"}}, orgs: []Org{acme, beta}, wantErr: "multiple organizations are available"},
		{name: "many without terminal", orgs: []Org{acme, beta}, wantErr: "multiple organizations are available (acme, beta) - pass --org <name>"},
		{name: "prompt", picker: InstallationPicker{Interactive: true, In: strings.NewReader("2\n")}, orgs: []Org{acme, beta}, want: beta, wantPrompts: true},
		{name: "prompt without newline", picker: InstallationPicker{Interactive: true, In: strings.NewReader("1")}, orgs: []Org{acme, beta}, want: acme, wantPrompts: true},
		{name: "prompt out of range", picker: InstallationPicker{Interactive: true, In: strings.NewReader("3\n")}, orgs: []Org{acme, beta}, wantErr: "invalid selection", wantPrompts: true},
		{name: "prompt not a number", picker: InstallationPicker{Interactive: true, In: strings.NewReader("acme\n")}, orgs: []Org{acme, beta}, wantErr: "invalid selection", wantPrompts: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			picker := tt.picker
			picker.Out = &out

			got, err := picker.Pick(tt.orgs)

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
				require.Contains(t, out.String(), "1) acme (githubOwnerId 1) on acme.nullify.ai")
				require.Contains(t, out.String(), "2) beta (githubOwnerId 2) on beta.nullify.ai")
			} else {
				require.Empty(t, out.String())
			}
		})
	}
}

func TestFetchOrgsSendsBearerToRouter(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/admin/installations", r.URL.Path)
		assert.Equal(t, "Bearer router-token", r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(installationsBody(entry("acme", "https://api.acme.nullify.ai", "7"))))
	})

	authHosts := recordAuthHosts(t)

	got, err := fetchOrgs(context.Background(), "api.nullify.ai", "router-token")
	require.NoError(t, err)
	require.Equal(t, []string{"api.nullify.ai"}, *authHosts)
	require.Equal(t, []Org{{Name: "acme", Key: "githubOwnerId", ID: "7", Host: "api.acme.nullify.ai"}}, got)
}

func TestFetchOrgsReportsServerError(t *testing.T) {
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	_, err := fetchOrgs(context.Background(), "api.nullify.ai", "router-token")
	require.Error(t, err)
	require.False(t, errors.Is(err, errNoUsableInstallation))
}

// An org the router reports pending or unavailable is not usable on its host
// even when its base URL names that host.
func TestPendingOrgOnTheHostIsNotUsable(t *testing.T) {
	body := `{"installations":[` +
		`{"name":"ready","provider":{},"nullifyBaseUrl":"https://api.acme.nullify.ai","queryParameters":{"githubOwnerId":"1"},"provisioningStatus":"ready"},` +
		`{"name":"held","provider":{},"nullifyBaseUrl":"https://api.acme.nullify.ai","queryParameters":{"githubOwnerId":"2"},"provisioningStatus":"pending"}]}`
	newAuthServer(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) })

	list, err := ListOrgs(context.Background(), "acme.nullify.ai", "api.nullify.ai", "router-token")
	require.NoError(t, err)
	require.Len(t, list.Orgs, 1)
	require.Equal(t, "ready", list.Orgs[0].Name)
	require.Len(t, list.Pending, 1)
	require.Equal(t, "held", list.Pending[0].Name)
	_, err = ResolveOrg("acme.nullify.ai", list, OrgInputs{Flag: "held", FlagSource: "--org"})
	require.ErrorContains(t, err, "not routed to a Nullify host yet")
}
