package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
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

	return os.WriteFile(path, data, 0600)
}

func SaveHostCredentials(host string, hostCreds HostCredentials) error {
	creds, err := LoadCredentials()
	if err != nil {
		creds = make(Credentials)
	}

	creds[host] = hostCreds

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

	delete(creds, host)

	return SaveCredentials(creds)
}
