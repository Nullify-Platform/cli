package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Org is one organization a request can be scoped to on an API host. Key and
// ID are the query parameter that scopes a request to it, e.g.
// githubOwnerId=1001001.
type Org struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Key      string `json:"key"`
	ID       string `json:"id"`
	// Host is the API host serving the org, empty when the router has not
	// routed it yet.
	Host string `json:"host,omitempty"`
	// Status is the router's provisioning status: ready, pending or
	// unavailable. Empty outside router mode.
	Status string `json:"status,omitempty"`
}

// DataHost is the org's API host in credential key form, "" when unrouted.
func (o Org) DataHost() string {
	return CredentialKey(o.Host)
}

// Query returns the query parameters that scope a request to the org.
func (o Org) Query() map[string]string {
	return map[string]string{o.Key: o.ID}
}

func (o Org) String() string {
	return fmt.Sprintf("%s (%s %s)", o.Name, o.Key, o.ID)
}

// Matches reports whether ref names the org, by name (case-insensitive) or id.
func (o Org) Matches(ref string) bool {
	ref = strings.TrimSpace(ref)
	return ref != "" && (strings.EqualFold(o.Name, ref) || o.ID == ref)
}

// OrgList is what the signed-in user can see from one API host.
type OrgList struct {
	// Orgs are served by this host and can scope its requests.
	Orgs []Org
	// Pending are the user's orgs the router has not finished routing.
	Pending []Org
	// Elsewhere are the user's orgs served by another Nullify host.
	Elsewhere []Org
}

// providerKeys maps a provider family to the query parameter that scopes a
// request to one of its orgs.
var providerKeys = map[string]string{
	"github":    "githubOwnerId",
	"azure":     "azureOrganizationId",
	"bitbucket": "bitbucketWorkspaceId",
	"gitlab":    "gitlabGroupId",
}

type installationsResponse struct {
	Installations []struct {
		Name     string `json:"name"`
		Provider struct {
			ID        string          `json:"id"`
			GitHub    json.RawMessage `json:"github"`
			Azure     json.RawMessage `json:"azure"`
			Bitbucket json.RawMessage `json:"bitbucket"`
			GitLab    json.RawMessage `json:"gitlab"`
		} `json:"provider"`
		NullifyBaseURL     *string           `json:"nullifyBaseUrl"`
		QueryParameters    map[string]string `json:"queryParameters"`
		ProvisioningStatus string            `json:"provisioningStatus"`
	} `json:"installations"`
}

// ListOrgs returns the orgs token can scope requests to on host, read from
// GET /admin/installations on listHost: the router for a router login, the
// tenant itself for a legacy login or an API token. An org counts for host
// when its nullifyBaseUrl names host; when listHost is host itself, an
// installation with no base URL is the tenant's own.
func ListOrgs(ctx context.Context, host, listHost, token string) (OrgList, error) {
	orgs, err := fetchOrgs(ctx, listHost, token)
	if err != nil {
		return OrgList{}, err
	}
	return sortOrgs(host, listHost, orgs), nil
}

// fetchOrgs reads every installation listHost reports for token. On a router
// an org's Host is set only when its base URL is one of that router's tenant
// origins; any other base URL marks the org unavailable and is never used.
func fetchOrgs(ctx context.Context, listHost, token string) ([]Org, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authBaseURL(listHost)+"/admin/installations", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := authClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		err := fmt.Errorf("list organizations on %s: status %d: %s", apiHost(listHost), resp.StatusCode, string(body))
		if resp.StatusCode == http.StatusUnauthorized {
			err = fmt.Errorf("%w: %w", ErrTokenRejected, err)
		}
		return nil, err
	}

	var out installationsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode organizations: %w", err)
	}

	router, onRouter := RouterFor(listHost)
	orgs := make([]Org, 0, len(out.Installations))
	for _, inst := range out.Installations {
		family := providerFamily(inst.Provider.ID, inst.Provider.GitHub, inst.Provider.Azure, inst.Provider.Bitbucket, inst.Provider.GitLab)
		key := orgKey(family, inst.QueryParameters)
		id := inst.QueryParameters[key]
		if key == "" || id == "" {
			continue
		}
		org := Org{Name: inst.Name, Provider: family, Key: key, ID: id, Status: inst.ProvisioningStatus}

		if inst.NullifyBaseURL != nil {
			if !onRouter {
				org.Host = baseURLHost(*inst.NullifyBaseURL)
			} else if dataHost, err := router.dataHost(strings.TrimSpace(*inst.NullifyBaseURL)); err == nil {
				org.Host = apiHost(dataHost)
			}
			if org.Host == "" {
				org.Status = "unavailable"
			}
		}
		orgs = append(orgs, org)
	}
	return orgs, nil
}

// orgKey is the query parameter that scopes a request to an org of family,
// or, when the router did not say which provider it is, the one known
// parameter its queryParameters carry.
func orgKey(family string, query map[string]string) string {
	if key := providerKeys[family]; key != "" {
		return key
	}
	found := ""
	for _, key := range providerKeys {
		if query[key] == "" {
			continue
		}
		if found != "" {
			return ""
		}
		found = key
	}
	return found
}

func sortOrgs(host, listHost string, orgs []Org) OrgList {
	target := strings.ToLower(apiHost(host))
	listIsTarget := strings.EqualFold(apiHost(listHost), target)

	var list OrgList
	for _, org := range orgs {
		switch {
		case org.Host == target && (org.Status == "pending" || org.Status == "unavailable"):
			list.Pending = append(list.Pending, org)
		case org.Host == target:
			list.Orgs = append(list.Orgs, org)
		case org.Host != "":
			list.Elsewhere = append(list.Elsewhere, org)
		case org.Status == "pending" || org.Status == "unavailable":
			list.Pending = append(list.Pending, org)
		case listIsTarget:
			org.Host = target
			list.Orgs = append(list.Orgs, org)
		default:
			list.Pending = append(list.Pending, org)
		}
	}

	for _, orgs := range [][]Org{list.Orgs, list.Pending, list.Elsewhere} {
		sort.Slice(orgs, func(i, j int) bool { return strings.ToLower(orgs[i].Name) < strings.ToLower(orgs[j].Name) })
	}
	return list
}

func providerFamily(id string, github, azure, bitbucket, gitlab json.RawMessage) string {
	present := func(raw json.RawMessage) bool { return len(raw) > 0 && string(raw) != "null" }
	switch {
	case present(github):
		return "github"
	case present(azure):
		return "azure"
	case present(bitbucket):
		return "bitbucket"
	case present(gitlab):
		return "gitlab"
	}
	return strings.ToLower(id)
}

// baseURLHost returns the API host a tenant's nullifyBaseUrl names, lower
// case and without a default port, or "" when it is not a plain https origin.
// It accepts what the router's own route validation accepts.
func baseURLHost(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return ""
	}
	if u.Path != "" && u.Path != "/" {
		return ""
	}
	if port := u.Port(); port != "" && port != "443" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// OrgPick is an org the user chose explicitly for a host, with `nullify org
// use` or at the prompt. It is the only scope the CLI remembers.
type OrgPick struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	ID   string `json:"id"`
}

// OrgInputs are the ways a command can name its org, in precedence order.
type OrgInputs struct {
	// Flag is --org, or a caller's equivalent (an MCP tool's org argument).
	Flag string
	// FlagSource names Flag in errors, e.g. "--org".
	FlagSource string
	// EnvOrg is NULLIFY_ORG.
	EnvOrg string
	// EnvGitHubOwnerID is NULLIFY_GITHUB_OWNER_ID.
	EnvGitHubOwnerID string
	// Stored is the remembered pick for this host.
	Stored *OrgPick
	// GitOwner is the owner in the current directory's git remote.
	GitOwner string
	// AnyHost lets an explicit name or id match an org on another host of
	// the same router, for a command that moves to that org's host.
	AnyHost bool
}

// ErrOrgNotChosen reports that several orgs could serve the request and
// nothing chose one. Orgs lists the choices.
type ErrOrgNotChosen struct {
	Host string
	Orgs []Org
	// Unavailable is the remembered org when it is no longer one of Orgs.
	Unavailable *OrgPick
}

func (e *ErrOrgNotChosen) Error() string {
	names := make([]string, len(e.Orgs))
	for i, o := range e.Orgs {
		names[i] = o.String()
	}
	if e.Unavailable != nil {
		return fmt.Sprintf("your default organization %s (%s %s) is not available on %s; choose one with --org <name|id> or 'nullify org use': %s",
			e.Unavailable.Name, e.Unavailable.Key, e.Unavailable.ID, e.Host, strings.Join(names, ", "))
	}
	return fmt.Sprintf("%s serves %d organizations; choose one with --org <name|id>, NULLIFY_ORG, or 'nullify org use': %s",
		e.Host, len(e.Orgs), strings.Join(names, ", "))
}

// ErrTokenRejected reports that the org list refused the token, which can
// happen before its stored expiry (revocation, clock skew).
var ErrTokenRejected = errors.New("token rejected")

// ErrOrgNotFound reports that an org named by the user is not one of theirs
// on this host.
var ErrOrgNotFound = errors.New("organization not available")

// ErrNoOrgs reports that the user has no org routed to this host.
var ErrNoOrgs = errors.New("no organization on this host is available to you")

// ResolveOrg picks the org a request on host runs as; see ResolveOrgReason.
func ResolveOrg(host string, list OrgList, in OrgInputs) (Org, error) {
	org, _, err := ResolveOrgReason(host, list, in)
	return org, err
}

// ResolveOrgReason picks the org a request on host runs as, from list and in,
// and says which rule picked it: an explicit name or id (--org, then
// NULLIFY_ORG, then NULLIFY_GITHUB_OWNER_ID), the git remote owner if it
// names exactly one org, the remembered pick, the only org. An explicit name
// that matches nothing is an error, never a fallthrough, and so is a
// remembered pick that is no longer available: another org is never put in
// its place. Anything left ambiguous returns *ErrOrgNotChosen; the lowest id
// is never a default.
func ResolveOrgReason(host string, list OrgList, in OrgInputs) (Org, string, error) {
	explicit := []struct{ ref, source string }{
		{in.Flag, in.FlagSource},
		{in.EnvOrg, "NULLIFY_ORG"},
	}
	for _, e := range explicit {
		if strings.TrimSpace(e.ref) == "" {
			continue
		}
		org, err := findOrg(host, list, e.ref, e.source, in.AnyHost)
		return org, e.source, err
	}
	if id := strings.TrimSpace(in.EnvGitHubOwnerID); id != "" {
		for _, o := range list.Orgs {
			if o.Key == "githubOwnerId" && o.ID == id {
				return o, "NULLIFY_GITHUB_OWNER_ID", nil
			}
		}
		return Org{}, "", notFound(host, list, id, "NULLIFY_GITHUB_OWNER_ID")
	}

	if owner := strings.TrimSpace(in.GitOwner); owner != "" {
		var match []Org
		for _, o := range list.Orgs {
			if strings.EqualFold(o.Name, owner) {
				match = append(match, o)
			}
		}
		if len(match) == 1 {
			return match[0], "git remote owner", nil
		}
	}

	if in.Stored != nil {
		for _, o := range list.Orgs {
			if o.Key == in.Stored.Key && o.ID == in.Stored.ID {
				return o, "your default", nil
			}
		}
		if len(list.Orgs) == 0 {
			return Org{}, "", noOrgs(host, list)
		}
		return Org{}, "", &ErrOrgNotChosen{Host: host, Orgs: list.Orgs, Unavailable: in.Stored}
	}

	switch len(list.Orgs) {
	case 0:
		return Org{}, "", noOrgs(host, list)
	case 1:
		return list.Orgs[0], "your only organization", nil
	default:
		return Org{}, "", &ErrOrgNotChosen{Host: host, Orgs: list.Orgs}
	}
}

func findOrg(host string, list OrgList, ref, source string, anyHost bool) (Org, error) {
	var match []Org
	for _, o := range list.Orgs {
		if o.Matches(ref) {
			match = append(match, o)
		}
	}
	if len(match) == 0 && anyHost {
		for _, o := range list.Elsewhere {
			if o.Matches(ref) && o.Status != "pending" && o.Status != "unavailable" {
				match = append(match, o)
			}
		}
	}
	switch len(match) {
	case 1:
		return match[0], nil
	case 0:
		return Org{}, notFound(host, list, ref, source)
	default:
		return Org{}, &ErrOrgNotChosen{Host: host, Orgs: match}
	}
}

func notFound(host string, list OrgList, ref, source string) error {
	for _, o := range list.Pending {
		if o.Matches(ref) {
			return fmt.Errorf("%w: %s %q: %s is not ready for use yet (status %s); try again later", ErrOrgNotFound, source, ref, o.Name, statusOr(o.Status, "pending"))
		}
	}
	for _, o := range list.Elsewhere {
		if o.Matches(ref) && (o.Status == "pending" || o.Status == "unavailable") {
			return fmt.Errorf("%w: %s %q: %s on %s is not ready for use yet (status %s); try again later", ErrOrgNotFound, source, ref, o.Name, o.Host, o.Status)
		}
		if o.Matches(ref) {
			return fmt.Errorf("%w: %s %q: %s is served by %s, not %s; use --host %s", ErrOrgNotFound, source, ref, o.Name, o.Host, apiHost(host), strings.TrimPrefix(o.Host, "api."))
		}
	}
	return fmt.Errorf("%w: %s %q is not one of your organizations on %s (%s)", ErrOrgNotFound, source, ref, apiHost(host), describeOrgs(list.Orgs))
}

func noOrgs(host string, list OrgList) error {
	if len(list.Pending) > 0 {
		return fmt.Errorf("%w: %s; %d of your organizations are not routed yet", ErrNoOrgs, apiHost(host), len(list.Pending))
	}
	return fmt.Errorf("%w: %s", ErrNoOrgs, apiHost(host))
}

func describeOrgs(orgs []Org) string {
	if len(orgs) == 0 {
		return "none available"
	}
	names := make([]string, len(orgs))
	for i, o := range orgs {
		names[i] = o.Name
	}
	return "available: " + strings.Join(names, ", ")
}

func statusOr(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
