package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialsRoundTrip(t *testing.T) {
	creds := Credentials{
		"api.test.nullify.ai": HostCredentials{
			AccessToken:  "test-token-123",
			RefreshToken: "refresh-456",
			ExpiresAt:    1700000000,
			QueryParameters: map[string]string{
				"orgId": "org-123",
			},
		},
	}

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded Credentials
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	hostCreds, ok := loaded["api.test.nullify.ai"]
	if !ok {
		t.Fatal("expected host credentials")
	}
	if hostCreds.AccessToken != "test-token-123" {
		t.Errorf("access_token = %q, want %q", hostCreds.AccessToken, "test-token-123")
	}
	if hostCreds.RefreshToken != "refresh-456" {
		t.Errorf("refresh_token = %q, want %q", hostCreds.RefreshToken, "refresh-456")
	}
	if hostCreds.QueryParameters["orgId"] != "org-123" {
		t.Errorf("query param orgId = %q, want %q", hostCreds.QueryParameters["orgId"], "org-123")
	}
}

func TestMultiHostCredentials(t *testing.T) {
	creds := make(Credentials)
	creds["host1.nullify.ai"] = HostCredentials{AccessToken: "token1", ExpiresAt: 100}
	creds["host2.nullify.ai"] = HostCredentials{AccessToken: "token2", ExpiresAt: 200}

	data, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded Credentials
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(loaded) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(loaded))
	}
	if loaded["host1.nullify.ai"].AccessToken != "token1" {
		t.Error("host1 token mismatch")
	}
	if loaded["host2.nullify.ai"].AccessToken != "token2" {
		t.Error("host2 token mismatch")
	}
}

func TestCredentialFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")

	creds := Credentials{
		"test.nullify.ai": HostCredentials{AccessToken: "secret"},
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	err = os.WriteFile(path, data, 0600)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestDeleteHostCredentials_FromMap(t *testing.T) {
	creds := Credentials{
		"host1.nullify.ai": HostCredentials{AccessToken: "token1"},
		"host2.nullify.ai": HostCredentials{AccessToken: "token2"},
	}

	delete(creds, "host1.nullify.ai")

	if _, ok := creds["host1.nullify.ai"]; ok {
		t.Error("expected host1 to be deleted")
	}
	if _, ok := creds["host2.nullify.ai"]; !ok {
		t.Error("expected host2 to still exist")
	}
}
