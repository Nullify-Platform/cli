package wizard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrUnreadableMCPConfig is returned for an existing MCP config file that is not a
// plain JSON object, such as one with comments or a trailing comma. Rewriting it
// would lose what it holds, so it is left unchanged.
var ErrUnreadableMCPConfig = errors.New("the MCP config file is not plain JSON")

// mcpServerName is the name of the nullify entry in every client's config.
const mcpServerName = "nullify"

// newMCPConfigMode is the mode of an MCP config file that did not exist yet.
const newMCPConfigMode fs.FileMode = 0o600

// mcpConfigFormat is how one client's MCP config file holds its servers.
type mcpConfigFormat struct {
	// key is the top-level object that holds the servers.
	key string
	// entry is the nullify server as the client expects it.
	entry map[string]any
}

// snippet returns the JSON that a person can add by hand: the nullify entry
// under its key.
func (f mcpConfigFormat) snippet() string {
	data, err := json.MarshalIndent(map[string]any{f.key: map[string]any{mcpServerName: f.entry}}, "", "  ")
	if err != nil {
		return fmt.Sprintf("%q: {%q: %v}", f.key, mcpServerName, f.entry)
	}
	return string(data)
}

// writeMCPConfig adds the nullify entry to the MCP config file at path and
// reports whether it added it. An entry that is already there is left alone. A
// file that cannot be parsed is refused with ErrUnreadableMCPConfig and never
// rewritten. The file is replaced in one rename and keeps its mode.
func writeMCPConfig(path string, format mcpConfigFormat) (bool, error) {
	target, err := resolveConfigPath(path)
	if err != nil {
		return false, err
	}

	config, mode, err := readMCPConfig(target)
	if err != nil {
		return false, err
	}

	servers, err := serversOf(target, config, format.key)
	if err != nil {
		return false, err
	}
	if _, ok := servers[mcpServerName]; ok {
		return false, nil
	}

	updated := withServer(config, format.key, servers, format.entry)
	data, err := json.MarshalIndent(updated, "", "  ")
	if err != nil {
		return false, fmt.Errorf("encode %s: %w", target, err)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return false, fmt.Errorf("create the directory of %s: %w", target, err)
	}
	if err := writeFileAtomic(target, append(data, '\n'), mode); err != nil {
		return false, err
	}
	return true, nil
}

// resolveConfigPath follows a symlink, so that the rename replaces the file it
// points at and not the link. A path that does not exist yet is returned as is.
func resolveConfigPath(path string) (string, error) {
	target, err := filepath.EvalSymlinks(path)
	switch {
	case err == nil:
		return target, nil
	case errors.Is(err, fs.ErrNotExist):
		if _, statErr := os.Lstat(path); errors.Is(statErr, fs.ErrNotExist) {
			return path, nil
		}
		return "", fmt.Errorf("resolve %s: %w", path, err)
	default:
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
}

// readMCPConfig returns the config object in the file and the file's mode. A
// missing or blank file is an empty object with the mode of a new file.
func readMCPConfig(path string) (map[string]any, fs.FileMode, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]any{}, newMCPConfigMode, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, info.Mode().Perm(), nil
	}

	var config map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !json.Valid(data) || decoder.Decode(&config) != nil || config == nil {
		return nil, 0, fmt.Errorf("%w: %s", ErrUnreadableMCPConfig, path)
	}
	return config, info.Mode().Perm(), nil
}

// serversOf returns the servers object under key, empty when the key is absent.
// A value of another type is refused, because replacing it would lose it.
func serversOf(path string, config map[string]any, key string) (map[string]any, error) {
	value, ok := config[key]
	if !ok || value == nil {
		return map[string]any{}, nil
	}
	servers, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q in %s is not an object", ErrUnreadableMCPConfig, key, path)
	}
	return servers, nil
}

// withServer returns a copy of config whose servers under key include the
// nullify entry. Neither config nor servers is changed.
func withServer(config map[string]any, key string, servers map[string]any, entry map[string]any) map[string]any {
	updatedServers := make(map[string]any, len(servers)+1)
	for name, server := range servers {
		updatedServers[name] = server
	}
	updatedServers[mcpServerName] = entry

	updated := make(map[string]any, len(config)+1)
	for k, v := range config {
		updated[k] = v
	}
	updated[key] = updatedServers
	return updated
}

// writeFileAtomic writes data to a temporary file next to path and renames it
// over path, so that a failure never leaves a half-written config.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
