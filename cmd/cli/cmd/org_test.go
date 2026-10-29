package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
	require.NoError(t, rememberOrg("acme.nullify.ai", testOrgA))

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

func TestStoredPickNoLongerAuthorizedFallsThrough(t *testing.T) {
	loginEnv(t)
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{testOrgB}}, nil
	})
	require.NoError(t, rememberOrg("acme.nullify.ai", testOrgA))

	authCtx, err := resolveCommandAuth(context.Background())
	require.NoError(t, err)
	require.Equal(t, "2002002", authCtx.QueryParams["githubOwnerId"])
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
	require.NoError(t, rememberOrg("acme.nullify.ai", testOrgB))

	configShowCmd.SetContext(context.Background())
	out := captureStdout(t, func() { require.NoError(t, configShowCmd.RunE(configShowCmd, nil)) })
	var shown map[string]string
	require.NoError(t, json.Unmarshal([]byte(out), &shown), out)
	require.Equal(t, map[string]string{
		"host":      "acme.nullify.ai",
		"auth":      "login",
		"auth_host": "api.nullify.ai",
		"org":       "acme-payments (githubOwnerId 2002002)",
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

// An --org that matches two orgs is settled at the prompt for this command
// only; it must not replace the remembered pick.
func TestAmbiguousExplicitOrgDoesNotChangeTheRememberedPick(t *testing.T) {
	loginEnv(t)
	dupGitHub := auth.Org{Name: "dup", Provider: "github", Key: "githubOwnerId", ID: "1", Host: "api.acme.nullify.ai"}
	dupGitLab := auth.Org{Name: "dup", Provider: "gitlab", Key: "gitlabGroupId", ID: "2", Host: "api.acme.nullify.ai"}
	stubOrgList(t, func(string) (auth.OrgList, error) {
		return auth.OrgList{Orgs: []auth.Org{dupGitHub, dupGitLab, testOrgA}}, nil
	})
	require.NoError(t, rememberOrg("acme.nullify.ai", testOrgA))
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
