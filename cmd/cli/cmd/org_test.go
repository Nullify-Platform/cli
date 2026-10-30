package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/stretchr/testify/require"
)

var (
	testOrgA = auth.Org{Name: "acme-web", Provider: "github", Key: "githubOwnerId", ID: "1001001", Host: "api.acme.nullify.ai"}
	testOrgB = auth.Org{Name: "acme-payments", Provider: "github", Key: "githubOwnerId", ID: "2002002", Host: "api.acme.nullify.ai"}
)

// stubOrgList replaces the org lister; list receives the host it was asked
// to list on.
func stubOrgList(t *testing.T, list func(listHost string) (auth.OrgList, error)) {
	t.Helper()
	old := listOrgs
	listOrgs = func(_ context.Context, _, listHost, _ string) (auth.OrgList, error) { return list(listHost) }
	t.Cleanup(func() { listOrgs = old })
}

// loginEnv sets up a browser login on acme bound to the router, with no
// token or org in the environment and a working directory outside any git
// repository.
func loginEnv(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	t.Setenv("NULLIFY_HOST", "acme.nullify.ai")
	t.Setenv("NULLIFY_TOKEN", "")
	t.Setenv("NULLIFY_ORG", "")
	t.Setenv("NULLIFY_GITHUB_OWNER_ID", "")
	t.Setenv("GITHUB_ACTIONS", "")

	require.NoError(t, auth.SaveHostCredentials("api.nullify.ai", auth.HostCredentials{
		AccessToken:     "router-token",
		RefreshToken:    "rt",
		ExpiresAt:       time.Now().Add(time.Hour).Unix(),
		QueryParameters: map[string]string{"githubOwnerId": "1001001"},
	}))
	require.NoError(t, auth.UpdateHostConfig("acme.nullify.ai", func(hc auth.HostConfig) auth.HostConfig {
		hc.AuthHost = "api.nullify.ai"
		return hc
	}))

	oldHost, oldToken, oldGithub, oldOrg := host, nullifyToken, githubToken, orgFlag
	host, nullifyToken, githubToken, orgFlag = "", "", "", ""
	t.Cleanup(func() { host, nullifyToken, githubToken, orgFlag = oldHost, oldToken, oldGithub, oldOrg })
}

func twoTestOrgs(t *testing.T) *[]string {
	listed := &[]string{}
	stubOrgList(t, func(listHost string) (auth.OrgList, error) {
		*listed = append(*listed, listHost)
		return auth.OrgList{Orgs: []auth.Org{testOrgA, testOrgB}}, nil
	})
	return listed
}

func TestResolveCommandAuthListsOrgsOnTheRouter(t *testing.T) {
	loginEnv(t)
	listed := twoTestOrgs(t)
	orgFlag = "acme-payments"

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "router-token", authCtx.Token)
	require.Equal(t, map[string]string{"githubOwnerId": "2002002"}, authCtx.QueryParams)
	require.Equal(t, []string{"api.nullify.ai"}, *listed)
}

// Two orgs, nothing chosen, no terminal: the command fails with the choices
// instead of falling back to the saved scope or the lowest id.
func TestResolveCommandAuthAmbiguousWithoutATerminal(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)

	_, err := resolveCommandAuth(context.Background())
	var notChosen *auth.ErrOrgNotChosen
	require.ErrorAs(t, err, &notChosen)
	require.Contains(t, err.Error(), "acme-web")
	require.Contains(t, err.Error(), "acme-payments")
}

func TestOrgEnvVarsBeatTheStoredPick(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	require.NoError(t, auth.SelectOrg(testOrgA))

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "1001001", authCtx.QueryParams["githubOwnerId"], "stored pick applies with nothing else set")

	t.Setenv("NULLIFY_GITHUB_OWNER_ID", "2002002")
	authCtx, err = resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "2002002", authCtx.QueryParams["githubOwnerId"], "NULLIFY_GITHUB_OWNER_ID beats the stored pick")

	t.Setenv("NULLIFY_GITHUB_OWNER_ID", "")
	t.Setenv("NULLIFY_ORG", "acme-payments")
	authCtx, err = resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "2002002", authCtx.QueryParams["githubOwnerId"], "NULLIFY_ORG beats the stored pick")

	orgFlag = "acme-web"
	authCtx, err = resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "1001001", authCtx.QueryParams["githubOwnerId"], "--org beats NULLIFY_ORG")
}

func TestPromptAnswerIsRemembered(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	var shown bytes.Buffer
	oldIn, oldOut := promptIn, promptOut
	promptIn, promptOut = strings.NewReader("2\n"), &shown
	t.Cleanup(func() { promptIn, promptOut = oldIn, oldOut })

	scope, err := resolveOrgScope(context.Background(), "acme.nullify.ai", "router-token", orgInputsFor("acme.nullify.ai", "", "--org"), true)
	require.NoError(t, err)
	require.Equal(t, testOrgB, *scope.Org)
	require.Contains(t, shown.String(), "1) acme-web")

	hosts, err := auth.LoadHosts()
	require.NoError(t, err)
	require.Equal(t, &auth.OrgPick{Name: "acme-payments", Key: "githubOwnerId", ID: "2002002"}, hosts["acme.nullify.ai"].Org)
	require.Equal(t, "api.nullify.ai", hosts["acme.nullify.ai"].AuthHost, "remembering the org keeps the auth host")

	// The next command, with no terminal, uses the remembered answer.
	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "2002002", authCtx.QueryParams["githubOwnerId"])
}

func TestPromptRejectsAnUnlistedAnswer(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	oldIn, oldOut := promptIn, promptOut
	promptIn, promptOut = strings.NewReader("someone-else\n"), &bytes.Buffer{}
	t.Cleanup(func() { promptIn, promptOut = oldIn, oldOut })

	_, err := resolveOrgScope(context.Background(), "acme.nullify.ai", "router-token", orgInputsFor("acme.nullify.ai", "", "--org"), true)
	require.Error(t, err)
	hosts, _ := auth.LoadHosts()
	require.Nil(t, hosts["acme.nullify.ai"].Org)
}

// A default org the user can no longer use stops the command and names it:
// running as the other org instead would act on the wrong one's data.
func TestUnavailableDefaultIsAnErrorNotAnotherOrg(t *testing.T) {
	loginEnv(t)
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{testOrgB}}, nil
	})
	require.NoError(t, auth.SelectOrg(testOrgA))

	_, err := resolveCommandAuth(context.Background())
	var notChosen *auth.ErrOrgNotChosen
	require.ErrorAs(t, err, &notChosen)
	require.Contains(t, err.Error(), "your default organization acme-web")
	require.Contains(t, err.Error(), "acme-payments")
}

func TestAPITokenOrgSelection(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_TOKEN", "api-token")
	listed := twoTestOrgs(t)

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Empty(t, authCtx.QueryParams, "the server takes an API token's own org")
	require.Empty(t, *listed, "no org list without an explicit org")

	t.Setenv("NULLIFY_GITHUB_OWNER_ID", "999")
	authCtx, err = resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, map[string]string{"githubOwnerId": "999"}, authCtx.QueryParams)
	require.Empty(t, *listed)

	t.Setenv("NULLIFY_GITHUB_OWNER_ID", "")
	orgFlag = "acme-web"
	authCtx, err = resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "1001001", authCtx.QueryParams["githubOwnerId"])
	require.Equal(t, []string{"acme.nullify.ai"}, *listed, "an API token lists on its own tenant, never the router")
}

func TestOrgUseRemembersThePick(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)

	orgUseCmd.SetContext(context.Background())
	require.NoError(t, orgUseCmd.RunE(orgUseCmd, []string{"2002002"}))

	hosts, err := auth.LoadHosts()
	require.NoError(t, err)
	require.Equal(t, "acme-payments", hosts["acme.nullify.ai"].Org.Name)

	err = orgUseCmd.RunE(orgUseCmd, []string{"nope"})
	require.Error(t, err)
	require.Equal(t, "acme-payments", mustLoadHosts(t)["acme.nullify.ai"].Org.Name, "a failed use keeps the old pick")
}

func TestOrgListFailureSurfaces(t *testing.T) {
	loginEnv(t)
	stubOrgList(t, func(string) (auth.OrgList, error) { return auth.OrgList{}, errors.New("router down") })

	_, err := resolveCommandAuth(context.Background())
	require.ErrorContains(t, err, "router down")
}

func mustLoadHosts(t *testing.T) auth.Hosts {
	t.Helper()
	hosts, err := auth.LoadHosts()
	require.NoError(t, err)
	return hosts
}

func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	run()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestAuthConfigShowsHostAuthHostAndOrg(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	require.NoError(t, auth.SelectOrg(testOrgB))

	configShowCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, configShowCmd.RunE(configShowCmd, nil)) })
	var shown map[string]string
	require.NoError(t, json.Unmarshal([]byte(out), &shown), out)
	require.Equal(t, map[string]string{
		"host":      "acme.nullify.ai",
		"auth":      "login",
		"auth_host": "api.nullify.ai",
		"data_host": "acme.nullify.ai",
		"org":       "acme-payments (githubOwnerId 2002002) on acme.nullify.ai (your default)",
	}, shown)

	t.Setenv("NULLIFY_TOKEN", "api-token")
	out = captureStdout(t, func() { require.NoError(t, configShowCmd.RunE(configShowCmd, nil)) })
	shown = nil
	require.NoError(t, json.Unmarshal([]byte(out), &shown), out)
	require.Equal(t, "api_token", shown["auth"])
	require.Equal(t, "the API token's own (the server derives it)", shown["org"])
	require.NotContains(t, shown, "auth_host")
}

func TestAuthStatusShowsTheOrg(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "acme.nullify.ai"}))

	statusCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(statusCmd, nil)) })
	require.Contains(t, out, "Auth host: api.nullify.ai")
	require.Contains(t, out, "Status: authenticated")
	require.Contains(t, out, "Org: not chosen")
	require.Contains(t, out, "acme-payments")
}

// The saved host is only the default: status for a tenant named by
// NULLIFY_HOST or --host must describe that tenant, and a mistyped --host is
// an error rather than "no host configured".
func TestAuthStatusUsesTheEffectiveHost(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "router.nullify.ai"}))

	statusCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(statusCmd, nil)) })
	require.Contains(t, out, "Host: acme.nullify.ai")
	require.Contains(t, out, "Auth host: api.nullify.ai")
	require.Contains(t, out, "acme-payments")

	host = "other.nullify.ai"
	out = captureStdout(t, func() { require.NoError(t, statusCmd.RunE(statusCmd, nil)) })
	require.Contains(t, out, "Host: other.nullify.ai")
	require.Contains(t, out, "Status: not authenticated")

	host = "acme.example.com"
	require.ErrorContains(t, statusCmd.RunE(statusCmd, nil), "invalid host")
}

// An --org that matches two orgs is settled at the prompt for this command
// only; it must not replace the remembered pick.
func TestAmbiguousExplicitOrgDoesNotChangeTheRememberedPick(t *testing.T) {
	loginEnv(t)
	dupGitHub := auth.Org{Name: "dup", Provider: "github", Key: "githubOwnerId", ID: "1", Host: "api.acme.nullify.ai"}
	dupGitLab := auth.Org{Name: "dup", Provider: "gitlab", Key: "gitlabGroupId", ID: "2", Host: "api.acme.nullify.ai"}
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{dupGitHub, dupGitLab, testOrgA}}, nil
	})
	require.NoError(t, auth.SelectOrg(testOrgA))
	oldIn, oldOut := promptIn, promptOut
	promptIn, promptOut = strings.NewReader("2\n"), &bytes.Buffer{}
	t.Cleanup(func() { promptIn, promptOut = oldIn, oldOut })

	scope, err := resolveOrgScope(context.Background(), "acme.nullify.ai", "router-token", orgInputsFor("acme.nullify.ai", "dup", "--org"), true)
	require.NoError(t, err)
	require.Equal(t, dupGitLab, *scope.Org)
	require.Equal(t, "acme-web", mustLoadHosts(t)["acme.nullify.ai"].Org.Name)
}

// A corrupt hosts.json must not break an API-token command, which never
// reads it.
func TestAPITokenIgnoresHostsFile(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_TOKEN", "api-token")
	require.NoError(t, os.WriteFile(os.Getenv("HOME")+"/.nullify/hosts.json", []byte("{broken"), 0600))

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Empty(t, authCtx.QueryParams)
}

// A host the user names is checked as the host a request would reach: a
// fragment, userinfo or port is refused before any token is read, and an
// invalid NULLIFY_HOST is an error rather than a reason to use the config.
func TestInvalidHostsAreRefusedBeforeAnyRequest(t *testing.T) {
	loginEnv(t)
	listed := twoTestOrgs(t)

	for _, bad := range []string{"api.attacker.example#.nullify.ai", "attacker.example@acme.nullify.ai", "acme.nullify.ai:8443"} {
		host = bad
		_, err := resolveCommandAuth(context.Background())
		require.ErrorContains(t, err, "invalid host", bad)
	}
	host = ""

	t.Setenv("NULLIFY_HOST", "api.attacker.example#.nullify.ai")
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "acme.nullify.ai"}))
	_, err := resolveCommandAuth(context.Background())
	require.ErrorContains(t, err, "invalid NULLIFY_HOST")
	require.Empty(t, *listed, "no request went anywhere")
}

// Upgrading from CLI v0.26.0: its router login selected globex-web on globex
// and left no hosts file. This version keeps that choice, and when it is no
// longer available says so instead of running as the other org.
func TestV026RouterLoginUpgrade(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Chdir(t.TempDir())
	for _, env := range []string{"NULLIFY_HOST", "NULLIFY_TOKEN", "NULLIFY_ORG", "NULLIFY_GITHUB_OWNER_ID", "GITHUB_ACTIONS"} {
		t.Setenv(env, "")
	}
	resetCommandFlags(t)
	oldOrg := orgFlag
	orgFlag = ""
	t.Cleanup(func() { orgFlag = oldOrg })

	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "nullify.ai"}))
	require.NoError(t, auth.SaveHostCredentials("nullify.ai", auth.HostCredentials{
		AccessToken:     "router-token",
		RefreshToken:    "rt",
		ExpiresAt:       time.Now().Add(time.Hour).Unix(),
		DataHost:        "globex.nullify.ai",
		Installation:    "globex-web",
		QueryParameters: map[string]string{"githubOwnerId": "5005005"},
	}))

	opsOrg := auth.Org{Name: "globex-ops", Provider: "github", Key: "githubOwnerId", ID: "6006006", Host: "api.globex.nullify.ai"}
	webOrg := auth.Org{Name: "globex-web", Provider: "github", Key: "githubOwnerId", ID: "5005005", Host: "api.globex.nullify.ai"}
	orgs := []auth.Org{opsOrg, webOrg}
	var listedOn []string
	stubOrgList(t, func(listHost string) (auth.OrgList, error) {
		listedOn = append(listedOn, listHost)
		return auth.OrgList{Orgs: orgs}, nil
	})

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "globex.nullify.ai", authCtx.DataHost)
	require.Equal(t, map[string]string{"githubOwnerId": "5005005"}, authCtx.QueryParams)
	require.Equal(t, []string{"api.nullify.ai"}, listedOn, "the org list comes from the router")

	orgFlag = "globex-ops"
	authCtx, err = resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, map[string]string{"githubOwnerId": "6006006"}, authCtx.QueryParams)
	orgFlag = ""

	orgs = []auth.Org{opsOrg}
	_, err = resolveCommandAuth(context.Background())
	require.ErrorContains(t, err, "your default organization globex-web")
}

// An API token in the environment wins over a stored login; status says so,
// since a forgotten NULLIFY_TOKEN makes a fresh login look like it did nothing.
func TestAuthStatusNotesAnEnvTokenOverridingTheLogin(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	t.Setenv("NULLIFY_TOKEN", "api-token")
	require.NoError(t, auth.SaveHostCredentials("acme.nullify.ai", auth.HostCredentials{AccessToken: "tenant"}))

	statusCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(statusCmd, nil)) })
	require.Contains(t, out, "Auth: API token")
	require.Contains(t, out, "overrides your 'nullify auth login' session")
}

// 'nullify org use' with an org on another tenant of the router moves plain
// commands there: the router's selected data host, the default host and that
// tenant's default all follow, as 'auth switch --installation' does.
func TestOrgUseMovesToAnotherTenantOfTheRouter(t *testing.T) {
	loginEnv(t)
	beta := auth.Org{Name: "beta-org", Provider: "github", Key: "githubOwnerId", ID: "3003003", Host: "api.beta.nullify.ai"}
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{testOrgA, testOrgB}, Elsewhere: []auth.Org{beta}}, nil
	})

	orgUseCmd.SetContext(context.Background())
	captureStdout(t, func() { require.NoError(t, orgUseCmd.RunE(orgUseCmd, []string{"3003003"})) })

	creds, err := auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "beta.nullify.ai", creds["nullify.ai"].DataHost)
	require.Equal(t, map[string]string{"githubOwnerId": "3003003"}, creds["nullify.ai"].QueryParameters)
	cfg, err := auth.LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "nullify.ai", cfg.Host)
	authHost, err := auth.AuthHostFor("beta.nullify.ai")
	require.NoError(t, err)
	require.Equal(t, "api.nullify.ai", authHost)
	require.Equal(t, "3003003", auth.StoredPick("beta.nullify.ai").ID)
}

// The hidden 'auth switch --installation' alias saves through the same writer
// as 'nullify org use', and refuses a host that is not a router.
func TestAuthSwitchInstallationAlias(t *testing.T) {
	loginEnv(t)
	fake := &fakeNullify{live: "router-token"}
	old := http.DefaultTransport
	http.DefaultTransport = fake
	t.Cleanup(func() { http.DefaultTransport = old })
	require.NoError(t, auth.SaveHostCredentials("nullify.ai", auth.HostCredentials{
		AccessToken: "router-token", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	require.NoError(t, switchCmd.Flags().Set("installation", "acme-payments"))
	t.Cleanup(func() { _ = switchCmd.Flags().Set("installation", "") })

	host = "acme.nullify.ai"
	require.ErrorContains(t, switchCmd.RunE(switchCmd, nil), "applies to a Nullify router host")

	host = "nullify.ai"
	switchCmd.SetContext(context.Background())
	captureStdout(t, func() { require.NoError(t, switchCmd.RunE(switchCmd, nil)) })
	creds, err := auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", creds["nullify.ai"].DataHost)
	require.Equal(t, map[string]string{"githubOwnerId": "2002002"}, creds["nullify.ai"].QueryParameters)
	require.Equal(t, "2002002", auth.StoredPick("acme.nullify.ai").ID, "same default 'org use' writes")
}

// An invalid host saved in the config is an error, not a reason to use
// another host.
func TestInvalidConfigHostIsAnError(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	t.Setenv("NULLIFY_HOST", "")
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "api.attacker.example#.nullify.ai"}))

	_, err := resolveCommandAuth(context.Background())
	require.ErrorContains(t, err, "in ~/.nullify/config.json")
}

// whoami on a router-bound tenant reports the router as its auth host, the
// tenant as its data host and the org commands run as.
func TestWhoamiReportsHostsAndOrg(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	require.NoError(t, auth.SelectOrg(testOrgB))

	whoamiCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, whoamiCmd.RunE(whoamiCmd, nil)) })
	var info map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &info), out)
	require.Equal(t, "acme.nullify.ai", info["host"])
	require.Equal(t, "api.nullify.ai", info["auth_host"])
	require.Equal(t, "acme.nullify.ai", info["data_host"])
	require.Equal(t, true, info["authenticated"])
	require.Contains(t, info["org"], "acme-payments")
}

// auth status and auth config report an invalid NULLIFY_HOST or config host
// as an error, not as "no host configured".
func TestAuthStatusReportsAnInvalidEnvOrConfigHost(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_HOST", "api.attacker.example#.nullify.ai")
	statusCmd.SetContext(context.Background())
	require.ErrorContains(t, statusCmd.RunE(statusCmd, nil), "invalid NULLIFY_HOST")
	configShowCmd.SetContext(context.Background())
	require.ErrorContains(t, configShowCmd.RunE(configShowCmd, nil), "invalid NULLIFY_HOST")

	t.Setenv("NULLIFY_HOST", "")
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "acme.nullify.ai:8443"}))
	require.ErrorContains(t, statusCmd.RunE(statusCmd, nil), "in ~/.nullify/config.json")
}

// Answering the org prompt during a command on a tenant remembers the org
// for that tenant without changing the default instance.
func TestPromptAnswerDoesNotMoveTheDefaultHost(t *testing.T) {
	loginEnv(t)
	twoTestOrgs(t)
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "own.nullify.ai"}))
	oldIn, oldOut := promptIn, promptOut
	promptIn, promptOut = strings.NewReader("2\n"), io.Discard
	t.Cleanup(func() { promptIn, promptOut = oldIn, oldOut })

	_, err := resolveOrgScope(context.Background(), "acme.nullify.ai", "router-token", orgInputsFor("acme.nullify.ai", "", "--org"), true)
	require.NoError(t, err)
	cfg, err := auth.LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "own.nullify.ai", cfg.Host)
	require.Equal(t, "2002002", auth.StoredPick("acme.nullify.ai").ID)
}

// 'nullify org list --org <org on another tenant>' on the router selects it,
// as a command with the same --org would run there.
func TestOrgListOnTheRouterSelectsAnOrgElsewhere(t *testing.T) {
	loginEnv(t)
	beta := auth.Org{Name: "beta-org", Provider: "github", Key: "githubOwnerId", ID: "3003003", Host: "api.beta.nullify.ai", Status: "ready"}
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{testOrgA, testOrgB}, Elsewhere: []auth.Org{beta}}, nil
	})

	out, err := orgListing(context.Background(), "acme.nullify.ai", "router-token", auth.OrgInputs{Flag: "beta-org", FlagSource: "--org", AnyHost: true})
	require.NoError(t, err)
	require.Equal(t, "beta-org", out["selected"])

	out, err = orgListing(context.Background(), "acme.nullify.ai", "router-token", auth.OrgInputs{Flag: "beta-org", FlagSource: "--org"})
	require.NoError(t, err)
	require.Nil(t, out["selected"], "off the router an org elsewhere is not selectable")
}

// The prompt's RememberOrg moves the router's selection only when it is
// already on that tenant.
func TestRememberOrgFollowsTheRouterSelectionOnlyOnItsTenant(t *testing.T) {
	loginEnv(t)
	require.NoError(t, auth.SaveHostCredentials("nullify.ai", auth.HostCredentials{AccessToken: "t", DataHost: "acme.nullify.ai", Installation: "acme-web",
		QueryParameters: map[string]string{"githubOwnerId": "1001001"}}))

	require.NoError(t, auth.RememberOrg(testOrgB))
	creds, err := auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "acme-payments", creds["nullify.ai"].Installation)
	require.Equal(t, map[string]string{"githubOwnerId": "2002002"}, creds["nullify.ai"].QueryParameters)

	beta := auth.Org{Name: "beta-org", Key: "githubOwnerId", ID: "3003003", Host: "api.beta.nullify.ai"}
	require.NoError(t, auth.UpdateHostConfig("beta.nullify.ai", func(hc auth.HostConfig) auth.HostConfig {
		hc.AuthHost = "api.nullify.ai"
		return hc
	}))
	require.NoError(t, auth.RememberOrg(beta))
	creds, err = auth.LoadCredentials()
	require.NoError(t, err)
	require.Equal(t, "acme.nullify.ai", creds["nullify.ai"].DataHost, "a pick on another tenant moved the router selection")
	require.Equal(t, "3003003", auth.StoredPick("beta.nullify.ai").ID)
}

// auth status with an API token reports an invalid NULLIFY_HOST as an error,
// and auth config an invalid config host.
func TestAuthStatusAndConfigReportInvalidHosts(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_TOKEN", "api-token")
	t.Setenv("NULLIFY_HOST", "api.attacker.example#.nullify.ai")
	statusCmd.SetContext(context.Background())
	require.ErrorContains(t, statusCmd.RunE(statusCmd, nil), "invalid NULLIFY_HOST")

	t.Setenv("NULLIFY_TOKEN", "")
	t.Setenv("NULLIFY_HOST", "")
	require.NoError(t, auth.SaveConfig(&auth.Config{Host: "acme.nullify.ai:8443"}))
	configShowCmd.SetContext(context.Background())
	require.ErrorContains(t, configShowCmd.RunE(configShowCmd, nil), "in ~/.nullify/config.json")
}

// A command on a tenant the router login might cover reports a failed check
// of that, not "not authenticated".
func TestCommandSurfacesAFailedRouterCoverageCheck(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_HOST", "beta.nullify.ai")
	oldCover := coverTenant
	t.Cleanup(func() { coverTenant = oldCover })
	coverTenant = func(context.Context, string) (bool, error) {
		return false, errors.New("could not check whether your nullify.ai login covers beta.nullify.ai: status 502")
	}

	_, err := resolveCommandAuth(context.Background())
	require.ErrorContains(t, err, "could not check whether your nullify.ai login covers beta.nullify.ai")
}

// 'nullify org use' moving to another instance warns when NULLIFY_HOST still
// pins plain commands to the old one, in any spelling of it, and says
// nothing when the org is on the pinned tenant, when the pin is the router,
// when nothing is pinned, or when --host names this command's host only.
func TestOrgUseNotesAPinnedNullifyHost(t *testing.T) {
	beta := auth.Org{Name: "beta-org", Provider: "github", Key: "githubOwnerId", ID: "3003003", Host: "api.beta.nullify.ai", Status: "ready"}
	run := func(t *testing.T, envHost, flagHost, org string) string {
		t.Helper()
		loginEnv(t)
		stubOrgList(t, func(string) (auth.OrgList, error) {
			return auth.OrgList{Orgs: []auth.Org{testOrgA, testOrgB}, Elsewhere: []auth.Org{beta}}, nil
		})
		t.Setenv("NULLIFY_HOST", envHost)
		host = flagHost
		if envHost == "" && flagHost == "" {
			// The saved host is a default, not a pin.
			require.NoError(t, auth.SaveConfig(&auth.Config{Host: "acme.nullify.ai"}))
		}
		var note bytes.Buffer
		oldOut := promptOut
		promptOut = &note
		t.Cleanup(func() { promptOut = oldOut })
		orgUseCmd.SetContext(context.Background())
		captureStdout(t, func() { require.NoError(t, orgUseCmd.RunE(orgUseCmd, []string{org})) })
		return note.String()
	}

	for _, env := range []string{"acme.nullify.ai", "https://ACME.nullify.ai/", "acme", "api.acme.nullify.ai"} {
		t.Run("moved away from "+env, func(t *testing.T) {
			require.Contains(t, run(t, env, "", "beta-org"), "NULLIFY_HOST still points commands at acme.nullify.ai")
		})
		t.Run("stayed on "+env, func(t *testing.T) {
			require.Empty(t, run(t, env, "", "acme-payments"))
		})
	}
	t.Run("--host alone pins nothing", func(t *testing.T) {
		require.Empty(t, run(t, "", "acme.nullify.ai", "beta-org"))
	})
	t.Run("--host with NULLIFY_HOST still notes the env pin", func(t *testing.T) {
		require.Contains(t, run(t, "acme.nullify.ai", "acme.nullify.ai", "beta-org"), "NULLIFY_HOST still points commands at acme.nullify.ai")
	})
	t.Run("pinned to the router", func(t *testing.T) {
		require.Empty(t, run(t, "nullify.ai", "acme.nullify.ai", "beta-org"))
	})
	t.Run("only a saved host", func(t *testing.T) {
		require.Empty(t, run(t, "", "", "beta-org"))
	})
}

// 'nullify org list --org <org on another tenant>' on the router, run as a
// command, selects it as the command would.
func TestOrgListCommandOnTheRouterSelectsAnOrgElsewhere(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_HOST", "nullify.ai")
	require.NoError(t, auth.SaveHostCredentials("nullify.ai", auth.HostCredentials{
		AccessToken: "router-token", RefreshToken: "rt", ExpiresAt: time.Now().Add(time.Hour).Unix(), DataHost: "acme.nullify.ai",
	}))
	beta := auth.Org{Name: "beta-org", Provider: "github", Key: "githubOwnerId", ID: "3003003", Host: "api.beta.nullify.ai", Status: "ready"}
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{testOrgA, testOrgB}, Elsewhere: []auth.Org{beta}}, nil
	})
	orgFlag = "beta-org"

	orgListCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, orgListCmd.RunE(orgListCmd, nil)) })
	var listed map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &listed), out)
	require.Equal(t, "beta-org", listed["selected"])
}

// auth status on a router login with no selected data host points to a new
// login, not to 'nullify org use', which cannot run without one.
func TestAuthStatusWithoutADataHostPointsToLogin(t *testing.T) {
	loginEnv(t)
	t.Setenv("NULLIFY_HOST", "nullify.ai")
	require.NoError(t, auth.SaveHostCredentials("nullify.ai", auth.HostCredentials{AccessToken: "router-token", ExpiresAt: time.Now().Add(time.Hour).Unix()}))

	statusCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, statusCmd.RunE(statusCmd, nil)) })
	require.Contains(t, out, "Data host: none selected - run 'nullify auth login'")
}
