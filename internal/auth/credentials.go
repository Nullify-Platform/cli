package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type HostCredentials struct {
	AccessToken     string            `json:"access_token"`
	RefreshToken    string            `json:"refresh_token"`
	ExpiresAt       int64             `json:"expires_at"`
	QueryParameters map[string]string `json:"query_parameters,omitempty"`
}

type Credentials map[string]HostCredentials

func credentialsPath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials.json"), nil
}

func LoadCredentials() (Credentials, error) {
	path, err := credentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var creds Credentials
	err = json.Unmarshal(data, &creds)
	if err != nil {
		return nil, err
	}

	return creds, nil
}

func SaveCredentials(creds Credentials) error {
	err := ensureConfigDir()
	if err != nil {
		return err
	}

	path, err := credentialsPath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return err
	}

	return atomicWriteFile(path, data, 0600)
}

// atomicWriteFile writes data to a temp file then renames it into place,
// preventing corruption on concurrent writes or crashes.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

// CredentialKey normalizes a host to its bare form (without "api." prefix)
// so that credentials are stored and looked up consistently regardless of
// whether the caller passes "acme.nullify.ai" or "api.acme.nullify.ai".
func CredentialKey(host string) string {
	return strings.TrimPrefix(host, "api.")
}

func SaveHostCredentials(host string, hostCreds HostCredentials) error {
	creds, err := LoadCredentials()
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("cannot update credentials: %w", err)
		}
		creds = make(Credentials)
	}

	creds[CredentialKey(host)] = hostCreds

	return SaveCredentials(creds)
}

func DeleteHostCredentials(host string) error {
	creds, err := LoadCredentials()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	delete(creds, CredentialKey(host))

	return SaveCredentials(creds)
}
