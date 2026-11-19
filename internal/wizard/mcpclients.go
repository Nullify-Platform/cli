package wizard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// claudeCommandTimeout bounds the run of 'claude mcp add'.
const claudeCommandTimeout = 30 * time.Second

// mcpEnv is what the MCP step reads from the machine and runs on it. Tests
// replace it, so that they never run the claude CLI.
type mcpEnv struct {
	projectRoot string
	// home is the home directory, empty when it is unknown.
	home     string
	lookPath func(file string) (string, error)
	// run runs a program and returns its combined output.
	run func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// systemMCPEnv is the working directory, the home directory, and the PATH of
// this process.
func systemMCPEnv() (mcpEnv, error) {
	projectRoot, err := os.Getwd()
	if err != nil {
		return mcpEnv{}, fmt.Errorf("failed to get working directory: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	return mcpEnv{
		projectRoot: projectRoot,
		home:        home,
		lookPath:    exec.LookPath,
		run:         runCommand,
	}, nil
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, claudeCommandTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// mcpServeArgs is the command that every client runs to start the server.
var mcpServeArgs = []string{"mcp", "serve"}

// claudeAddArgs adds the server to Claude Code's user scope, which is
// ~/.claude.json.
var claudeAddArgs = append([]string{"mcp", "add", "--scope", "user", mcpServerName, "--", "nullify"}, mcpServeArgs...)

var (
	// cursorFormat is .cursor/mcp.json.
	cursorFormat = mcpConfigFormat{
		key:   "mcpServers",
		entry: map[string]any{"command": "nullify", "args": mcpServeArgs},
	}
	// claudeProjectFormat is .mcp.json in the project root.
	claudeProjectFormat = mcpConfigFormat{
		key:   "mcpServers",
		entry: map[string]any{"command": "nullify", "args": mcpServeArgs},
	}
	// vscodeFormat is .vscode/mcp.json, whose servers are under "servers".
	vscodeFormat = mcpConfigFormat{
		key:   "servers",
		entry: map[string]any{"type": "stdio", "command": "nullify", "args": mcpServeArgs},
	}
)

// configureMCPClients configures each AI tool that it detects, and says so
// only for a config that the tool reads.
func configureMCPClients(ctx context.Context, out io.Writer, env mcpEnv) {
	configured := false

	if dirExists(filepath.Join(env.projectRoot, ".cursor")) {
		configured = configureByFile(out, "Cursor", filepath.Join(env.projectRoot, ".cursor", "mcp.json"), cursorFormat) || configured
	}
	if hasClaudeCode(env) {
		configured = configureClaudeCode(ctx, out, env) || configured
	}
	if dirExists(filepath.Join(env.projectRoot, ".vscode")) {
		configured = configureByFile(out, "VS Code", filepath.Join(env.projectRoot, ".vscode", "mcp.json"), vscodeFormat) || configured
	}

	if !configured {
		fmt.Fprintln(out, "  No AI tools detected. You can manually configure MCP by running 'nullify mcp serve'.")
	}
}

// hasClaudeCode reports whether Claude Code is installed: its CLI is on the
// PATH, or its user config exists.
func hasClaudeCode(env mcpEnv) bool {
	if _, err := env.lookPath("claude"); err == nil {
		return true
	}
	if env.home == "" {
		return false
	}
	return dirExists(filepath.Join(env.home, ".claude")) || fileExists(filepath.Join(env.home, ".claude.json"))
}

// configureClaudeCode adds the server with 'claude mcp add' when the CLI is on
// the PATH. Otherwise it writes .mcp.json in the project root, which Claude
// Code reads for the project.
func configureClaudeCode(ctx context.Context, out io.Writer, env mcpEnv) bool {
	if _, err := env.lookPath("claude"); err != nil {
		return configureByFile(out, "Claude Code", filepath.Join(env.projectRoot, ".mcp.json"), claudeProjectFormat)
	}

	output, err := env.run(ctx, "claude", claudeAddArgs...)
	if err == nil {
		fmt.Fprintln(out, "  Configured MCP for Claude Code (user scope)")
		return true
	}
	if strings.Contains(strings.ToLower(string(output)), "already exists") {
		fmt.Fprintln(out, "  Claude Code already has a nullify MCP server")
		return true
	}
	fmt.Fprintf(out, "  Did not configure Claude Code: 'claude %s' failed: %v\n", strings.Join(claudeAddArgs, " "), err)
	if text := strings.TrimSpace(string(output)); text != "" {
		fmt.Fprintln(out, indent(text, "    "))
	}
	fmt.Fprintf(out, "  Run it yourself, or add this entry to .mcp.json in the project root:\n%s\n", indent(claudeProjectFormat.snippet(), "    "))
	return false
}

// configureByFile adds the nullify entry to one client's config file, tells
// the person what happened, and reports whether the client is configured. A
// file that cannot be changed safely is left alone, and the person is shown the
// entry to add by hand.
func configureByFile(out io.Writer, client, path string, format mcpConfigFormat) bool {
	added, err := writeMCPConfig(path, format)
	switch {
	case errors.Is(err, ErrUnreadableMCPConfig):
		fmt.Fprintf(out, "  Did not configure %s: %s is not plain JSON (it may hold comments or a trailing comma), so it was left unchanged. Add this entry to it by hand:\n%s\n",
			client, path, indent(format.snippet(), "    "))
		return false
	case err != nil:
		fmt.Fprintf(out, "  Did not configure %s: %v. Add this entry to %s by hand:\n%s\n",
			client, err, path, indent(format.snippet(), "    "))
		return false
	case !added:
		fmt.Fprintf(out, "  %s already has a nullify MCP server (%s)\n", client, path)
		return true
	default:
		fmt.Fprintf(out, "  Configured MCP for %s (%s)\n", client, path)
		return true
	}
}

// indent prefixes every line of text with prefix.
func indent(text, prefix string) string {
	return prefix + strings.ReplaceAll(text, "\n", "\n"+prefix)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
