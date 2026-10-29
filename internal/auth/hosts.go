package auth

import (
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
// the router rather than the tenant itself.
type HostConfig struct {
	AuthHost string `json:"auth_host,omitempty"`
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
	hosts, err := LoadHosts()
	if err != nil {
		return err
	}

	next := maps.Clone(hosts)
	next[CredentialKey(host)] = update(hosts[CredentialKey(host)])

	return saveHosts(next)
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

// KnownHosts lists the API hosts the user has signed in to, sorted. Router
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
	for h := range hosts {
		known[h] = true
	}

	return slices.Sorted(maps.Keys(known)), nil
}
