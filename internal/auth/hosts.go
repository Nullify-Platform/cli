package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
)

// HostConfig is what the CLI remembers about one API host. AuthHost is the
// host that ran its login and serves its refresh, which on a router tenant is
// the router rather than the tenant itself. Org is the org the user picked
// for this host, if any.
type HostConfig struct {
	AuthHost string   `json:"auth_host,omitempty"`
	Org      *OrgPick `json:"org,omitempty"`
}

// Hosts maps an API host, in CredentialKey form, to its HostConfig. It lives
// apart from credentials.json because it holds no secrets, and apart from
// config.json because callers rewrite that file whole.
type Hosts map[string]HostConfig

func hostsPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hosts.json"), nil
}

// LoadHosts returns the stored host bindings, empty when none were saved.
func LoadHosts() (Hosts, error) {
	path, err := hostsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Hosts{}, nil
	}
	if err != nil {
		return nil, err
	}

	var hosts Hosts
	if err := json.Unmarshal(data, &hosts); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if hosts == nil {
		hosts = Hosts{}
	}
	return hosts, nil
}

func saveHosts(hosts Hosts) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}

	path, err := hostsPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(hosts, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(path, data, 0600)
}

// UpdateHostConfig applies update to the stored config for host and saves it.
func UpdateHostConfig(host string, update func(HostConfig) HostConfig) error {
	return updateHosts(func(hosts Hosts) Hosts {
		next := maps.Clone(hosts)
		next[CredentialKey(host)] = update(hosts[CredentialKey(host)])
		return next
	})
}

// updateHosts applies update to the stored host configs under the store lock
// and saves them.
func updateHosts(update func(Hosts) Hosts) error {
	return withStoreLock(func() error {
		hosts, err := LoadHosts()
		if err != nil {
			return err
		}
		return saveHosts(update(hosts))
	})
}

// AuthHostFor returns the host whose credentials serve host: the auth host
// recorded at login, or host itself for a login made before the CLI asked
// (those credentials are stored under the tenant's own key).
func AuthHostFor(host string) (string, error) {
	hosts, err := LoadHosts()
	if err != nil {
		return "", err
	}
	if hc, ok := hosts[CredentialKey(host)]; ok && hc.AuthHost != "" {
		return hc.AuthHost, nil
	}
	return host, nil
}

// LookupCredentials returns the stored credentials that serve host and the
// auth host they belong to. ok is false when none are stored.
func LookupCredentials(host string) (hostCreds HostCredentials, authHost string, ok bool, err error) {
	authHost, err = AuthHostFor(host)
	if err != nil {
		return HostCredentials{}, "", false, err
	}

	creds, err := LoadCredentials()
	if err != nil {
		return HostCredentials{}, authHost, false, err
	}

	hostCreds, ok = creds[CredentialKey(authHost)]
	return hostCreds, authHost, ok, nil
}

// KnownHosts lists the API hosts the user is signed in to, sorted. Router
// credentials are shared by the tenants bound to them, so the router's own key
// is listed only when no tenant is.
func KnownHosts() ([]string, error) {
	hosts, err := LoadHosts()
	if err != nil {
		return nil, err
	}
	creds, err := LoadCredentials()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	known := map[string]bool{}
	for h := range creds {
		known[h] = true
	}
	for h, hc := range hosts {
		if authKey := CredentialKey(hc.AuthHost); authKey != h {
			delete(known, authKey)
		}
	}
	// A bound host is known while the login behind it is: a logout removes
	// that login and, with it, every host signed in through it.
	for h, hc := range hosts {
		if _, ok := creds[CredentialKey(hc.AuthHost)]; ok && hc.AuthHost != "" {
			known[h] = true
		}
	}

	return slices.Sorted(maps.Keys(known)), nil
}

// StoredPick returns the org remembered for dataHost: the one saved by a
// login or 'nullify org use', else the installation a CLI v0.26.0 router
// login selected there, which this version takes over as the same choice.
// It is returned even when the org is no longer available, so the caller can
// say so instead of quietly using another.
func StoredPick(dataHost string) *OrgPick {
	key := CredentialKey(dataHost)
	if hosts, err := LoadHosts(); err == nil && hosts[key].Org != nil {
		return hosts[key].Org
	}

	creds, err := LoadCredentials()
	if err != nil {
		return nil
	}
	for _, r := range routers {
		rc := creds[r.Key]
		if rc.DataHost != key {
			continue
		}
		for _, k := range slices.Sorted(maps.Keys(rc.QueryParameters)) {
			if slices.Contains(slices.Collect(maps.Values(providerKeys)), k) && rc.QueryParameters[k] != "" {
				return &OrgPick{Name: rc.Installation, Key: k, ID: rc.QueryParameters[k]}
			}
		}
	}
	return nil
}

// CoverTenant binds tenant to a stored router login that lists one of the
// user's orgs on it, and reports whether one did: a router login covers every
// tenant it lists, including one added after the login.
func CoverTenant(ctx context.Context, tenant string) (bool, error) {
	if covered, err := CoverSelectedTenant(tenant); covered || err != nil {
		return covered, err
	}
	creds, err := LoadCredentials()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	var checkErr error
	for _, r := range routers {
		if _, ok := creds[r.Key]; !ok {
			continue
		}
		// A router only serves tenants under its own domain.
		if _, ok := r.tenantLabel(apiHost(CredentialKey(tenant))); !ok {
			continue
		}
		token, err := GetValidToken(ctx, r.Key)
		if err == nil {
			var orgs []Org
			if orgs, err = fetchOrgs(ctx, r.AuthHost, token); err == nil && len(orgsOn(routedOrgs(orgs), tenant)) > 0 {
				return true, BindTenant(tenant, r)
			}
		}
		if err != nil {
			checkErr = fmt.Errorf("could not check whether your %s login covers %s: %w", r.Key, tenant, err)
		}
	}
	return false, checkErr
}

// CoverSelectedTenant binds tenant to the router login whose selected data
// host it is, as a CLI v0.26.0 login leaves it, without asking the router.
func CoverSelectedTenant(tenant string) (bool, error) {
	creds, err := LoadCredentials()
	if err != nil {
		return false, nil
	}
	for _, r := range routers {
		if rc, ok := creds[r.Key]; ok && rc.DataHost == CredentialKey(tenant) {
			return true, BindTenant(tenant, r)
		}
	}
	return false, nil
}
