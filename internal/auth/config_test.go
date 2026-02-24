package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRoundTrip(t *testing.T) {
	// Test JSON serialization/deserialization
	cfg := &Config{Host: "api.test.nullify.ai"}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var loaded Config
	err = json.Unmarshal(data, &loaded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if loaded.Host != cfg.Host {
		t.Errorf("host = %q, want %q", loaded.Host, cfg.Host)
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	// Use temp dir and override via file operations
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	cfg := &Config{Host: "api.prod.nullify.ai"}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	err = os.WriteFile(path, data, 0644)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	readData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var loaded Config
	err = json.Unmarshal(readData, &loaded)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if loaded.Host != "api.prod.nullify.ai" {
		t.Errorf("host = %q, want %q", loaded.Host, "api.prod.nullify.ai")
	}
}
