package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

var (
	acmeWeb    = Org{Name: "acme-web", Provider: "github", Key: "githubOwnerId", ID: "1001001", Host: tenantAPI}
	acmePay    = Org{Name: "acme-payments", Provider: "github", Key: "githubOwnerId", ID: "2002002", Host: tenantAPI}
	pendingOrg = Org{Name: "newco", Provider: "github", Key: "githubOwnerId", ID: "555", Status: "pending"}
	otherStack = Org{Name: "elsewhere-inc", Provider: "github", Key: "githubOwnerId", ID: "666", Host: "api.other.nullify.ai"}
)

func twoOrgs() OrgList {
	return OrgList{Orgs: []Org{acmeWeb, acmePay}, Pending: []Org{pendingOrg}, Elsewhere: []Org{otherStack}}
}

func TestResolveOrgPrecedence(t *testing.T) {
	stored := &OrgPick{Name: "acme-payments", Key: "githubOwnerId", ID: "2002002"}
	stale := &OrgPick{Name: "gone", Key: "githubOwnerId", ID: "1"}

	tests := []struct {
		name string
		list OrgList
		in   OrgInputs
		want Org
	}{
		{"--org by name", twoOrgs(), OrgInputs{Flag: "ACME-WEB"}, acmeWeb},
		{"--org by id", twoOrgs(), OrgInputs{Flag: "2002002"}, acmePay},
		{"--org beats NULLIFY_ORG", twoOrgs(), OrgInputs{Flag: "acme-payments", EnvOrg: "acme-web"}, acmePay},
		{"NULLIFY_ORG beats NULLIFY_GITHUB_OWNER_ID", twoOrgs(), OrgInputs{EnvOrg: "acme-payments", EnvGitHubOwnerID: "1001001"}, acmePay},
		{"NULLIFY_GITHUB_OWNER_ID beats the stored pick", twoOrgs(), OrgInputs{EnvGitHubOwnerID: "1001001", Stored: stored}, acmeWeb},
		{"NULLIFY_ORG beats the stored pick", twoOrgs(), OrgInputs{EnvOrg: "acme-web", Stored: stored}, acmeWeb},
		{"git owner beats the stored pick", twoOrgs(), OrgInputs{Stored: stored, GitOwner: "acme-web"}, acmeWeb},
		{"stored pick no longer in the list falls through to the git owner", twoOrgs(), OrgInputs{Stored: stale, GitOwner: "ACME-WEB"}, acmeWeb},
		{"git owner names one org", twoOrgs(), OrgInputs{GitOwner: "acme-payments"}, acmePay},
		{"git owner matching nothing falls through to the sole org", OrgList{Orgs: []Org{acmeWeb}}, OrgInputs{GitOwner: "someone-else"}, acmeWeb},
		{"sole org", OrgList{Orgs: []Org{acmePay}, Pending: []Org{pendingOrg}}, OrgInputs{}, acmePay},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.in.FlagSource = "--org"
			got, err := ResolveOrg(tenantHost, tt.list, tt.in)
			if err != nil {
				t.Fatalf("ResolveOrg: %v", err)
			}
			if got != tt.want {
				t.Errorf("org = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveOrgNeverDefaultsToTheLowestID(t *testing.T) {
	stale := &OrgPick{Name: "gone", Key: "githubOwnerId", ID: "1"}
	_, err := ResolveOrg(tenantHost, twoOrgs(), OrgInputs{Stored: stale, GitOwner: "someone-else"})

	var notChosen *ErrOrgNotChosen
	if !errors.As(err, &notChosen) {
		t.Fatalf("err = %v, want *ErrOrgNotChosen", err)
	}
	if len(notChosen.Orgs) != 2 {
		t.Errorf("choices = %v, want both orgs", notChosen.Orgs)
	}
	for _, want := range []string{"acme-web", "acme-payments", "--org", "nullify org use"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestResolveOrgExplicitMissIsAnError(t *testing.T) {
	tests := []struct {
		name string
		in   OrgInputs
		want string
	}{
		{"unknown name does not fall through to the stored pick", OrgInputs{Flag: "nope", FlagSource: "--org", Stored: &OrgPick{Key: "githubOwnerId", ID: "2002002"}}, `--org "nope" is not one of your organizations`},
		{"unknown NULLIFY_ORG", OrgInputs{EnvOrg: "nope"}, `NULLIFY_ORG "nope"`},
		{"unknown NULLIFY_GITHUB_OWNER_ID", OrgInputs{EnvGitHubOwnerID: "999"}, `NULLIFY_GITHUB_OWNER_ID "999"`},
		{"pending route reported apart", OrgInputs{Flag: "newco", FlagSource: "--org"}, "not routed to a Nullify host yet (status pending)"},
		{"org on another host reported apart", OrgInputs{Flag: "elsewhere-inc", FlagSource: "--org"}, "served by api.other.nullify.ai"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ResolveOrg(tenantHost, twoOrgs(), tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

func TestResolveOrgWithNoOrgs(t *testing.T) {
	_, err := ResolveOrg(tenantHost, OrgList{Pending: []Org{pendingOrg}}, OrgInputs{})
	if !errors.Is(err, ErrNoOrgs) || !strings.Contains(err.Error(), "not routed yet") {
		t.Fatalf("err = %v, want ErrNoOrgs mentioning the pending org", err)
	}
}

const routerInstallations = `{"installations": [
  {"name": "acme-payments", "avatarUrl": "", "provider": {"id": "GitHub", "github": {"ownerId": 2002002}},
   "nullifyBaseUrl": "https://api.acme.nullify.ai", "queryParameters": {"githubOwnerId": "2002002"}, "provisioningStatus": "ready"},
  {"name": "acme-web", "avatarUrl": "", "provider": {"id": "GitHub", "github": {"ownerId": 1001001}},
   "nullifyBaseUrl": "https://API.acme.nullify.ai:443/", "queryParameters": {"githubOwnerId": "1001001"}, "provisioningStatus": "ready"},
  {"name": "elsewhere-inc", "avatarUrl": "", "provider": {"id": "GitHub", "github": {"ownerId": 666}},
   "nullifyBaseUrl": "https://api.other.nullify.ai", "queryParameters": {"githubOwnerId": "666"}, "provisioningStatus": "ready"},
  {"name": "newco", "avatarUrl": "", "provider": {"id": "GitHub", "github": {"ownerId": 555}},
   "queryParameters": {"githubOwnerId": "555"}, "provisioningStatus": "pending"},
  {"name": "pathy", "avatarUrl": "", "provider": {"id": "GitHub", "github": {"ownerId": 777}},
   "nullifyBaseUrl": "https://api.acme.nullify.ai/evil", "queryParameters": {"githubOwnerId": "777"}, "provisioningStatus": "ready"},
  {"name": "contoso", "avatarUrl": "", "provider": {"id": "Azure", "azure": {"organizationId": "c-1"}},
   "nullifyBaseUrl": "https://api.acme.nullify.ai", "queryParameters": {"azureOrganizationId": "c-1"}, "provisioningStatus": "ready"},
  {"name": "ws", "avatarUrl": "", "provider": {"id": "Bitbucket", "bitbucket": {"workspaceId": "w-1"}},
   "nullifyBaseUrl": "https://api.acme.nullify.ai", "queryParameters": {"bitbucketWorkspaceId": "w-1"}, "provisioningStatus": "ready"},
  {"name": "grp", "avatarUrl": "", "provider": {"id": "GitLab", "gitlab": {"groupId": 9}},
   "nullifyBaseUrl": "https://api.acme.nullify.ai", "queryParameters": {"gitlabGroupId": "9"}, "provisioningStatus": "ready"},
  {"name": "slack-only", "avatarUrl": "", "provider": {"id": "Slack", "slack": {}},
   "nullifyBaseUrl": "https://api.acme.nullify.ai", "queryParameters": {"slackTeamId": "T1"}, "provisioningStatus": "ready"}
]}`

func TestListOrgsFromTheRouter(t *testing.T) {
	var gotAuth string
	calls := newRoutedAuthServer(t, func(w http.ResponseWriter, r *http.Request, host, path string) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(routerInstallations))
	})

	list, err := ListOrgs(context.Background(), tenantHost, routerAPI, "router-token")
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != (hostCall{routerAPI, "/admin/installations"}) {
		t.Errorf("calls = %v, want one installations read on the router", *calls)
	}
	if gotAuth != "Bearer router-token" {
		t.Errorf("Authorization = %q, want the router token", gotAuth)
	}

	names := func(orgs []Org) string {
		var out []string
		for _, o := range orgs {
			out = append(out, o.Name+"="+o.Key+":"+o.ID)
		}
		return strings.Join(out, ",")
	}
	if got, want := names(list.Orgs), "acme-payments=githubOwnerId:2002002,acme-web=githubOwnerId:1001001,contoso=azureOrganizationId:c-1,grp=gitlabGroupId:9,ws=bitbucketWorkspaceId:w-1"; got != want {
		t.Errorf("orgs = %s\nwant   %s", got, want)
	}
	if got, want := names(list.Elsewhere), "elsewhere-inc=githubOwnerId:666"; got != want {
		t.Errorf("elsewhere = %s, want %s", got, want)
	}
	if got, want := names(list.Pending), "newco=githubOwnerId:555,pathy=githubOwnerId:777"; got != want {
		t.Errorf("pending = %s, want %s", got, want)
	}
}

// A legacy stack lists its own installations without base URLs.
func TestListOrgsFromTheTenantItself(t *testing.T) {
	newRoutedAuthServer(t, func(w http.ResponseWriter, _ *http.Request, host, _ string) {
		if host != tenantAPI {
			t.Errorf("listed on %s, want the tenant", host)
		}
		_, _ = w.Write([]byte(`{"installations": [{"name": "acme", "provider": {"id": "GitHub", "github": {}},` +
			` "queryParameters": {"githubOwnerId": "42"}}]}`))
	})

	list, err := ListOrgs(context.Background(), tenantHost, tenantHost, "tok")
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(list.Orgs) != 1 || list.Orgs[0].ID != "42" || list.Orgs[0].Host != tenantAPI {
		t.Errorf("orgs = %v, want the tenant's own org", list.Orgs)
	}
}

func TestListOrgsFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler func(w http.ResponseWriter)
		want    string
	}{
		{"unauthorized", func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) }, "status 401"},
		{"redirect is not followed", func(w http.ResponseWriter) {
			w.Header().Set("Location", "https://api.evil.example/admin/installations")
			w.WriteHeader(http.StatusFound)
		}, "status 302"},
		{"garbage", func(w http.ResponseWriter) { _, _ = w.Write([]byte("<html>")) }, "decode organizations"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newRoutedAuthServer(t, func(w http.ResponseWriter, _ *http.Request, _, _ string) { tt.handler(w) })
			_, err := ListOrgs(context.Background(), tenantHost, routerAPI, "tok")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// An org on another tenant that the router still reports pending or
// unavailable cannot be chosen there, so it never replaces a working default.
func TestAnyHostSkipsAnUnusableOrgOnAnotherTenant(t *testing.T) {
	ready := Org{Name: "beta-org", Key: "githubOwnerId", ID: "3003003", Host: "api.beta.nullify.ai", Status: "ready"}
	held := Org{Name: "gamma-org", Key: "githubOwnerId", ID: "4004004", Host: "api.gamma.nullify.ai", Status: "pending"}
	list := OrgList{Orgs: []Org{acmeWeb}, Elsewhere: []Org{ready, held}}

	org, err := ResolveOrg(tenantHost, list, OrgInputs{Flag: "beta-org", FlagSource: "--org", AnyHost: true})
	if err != nil || org.ID != "3003003" {
		t.Fatalf("org = %v, %v; want beta-org", org, err)
	}
	if _, err := ResolveOrg(tenantHost, list, OrgInputs{Flag: "gamma-org", FlagSource: "--org", AnyHost: true}); err == nil {
		t.Fatal("a pending org on another tenant was chosen")
	}
}
