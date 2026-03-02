package wizard

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"
)

// DomainStep checks if a valid host is configured and prompts the user if not.
func DomainStep() Step {
	return Step{
		Name: "Configure Nullify domain",
		Check: func(ctx context.Context) bool {
			cfg, err := auth.LoadConfig()
			return err == nil && cfg.Host != ""
		},
		Execute: func(ctx context.Context) error {
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("  Enter your Nullify customer name (e.g., 'acme'): ")
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			input = strings.TrimSpace(input)
			host, err := lib.ParseCustomerDomain(input)
			if err != nil {
				return fmt.Errorf("invalid domain: %w", err)
			}

			err = auth.SaveConfig(&auth.Config{Host: host})
			if err != nil {
				return fmt.Errorf("failed to save config: %w", err)
			}

			fmt.Printf("  Configured host: %s\n", host)
			return nil
		},
	}
}

// AuthStep checks if valid credentials exist and runs login if not.
func AuthStep() Step {
	return Step{
		Name: "Authenticate with Nullify",
		Check: func(ctx context.Context) bool {
			cfg, err := auth.LoadConfig()
			if err != nil || cfg.Host == "" {
				return false
			}
			_, err = auth.GetValidToken(ctx, cfg.Host)
			return err == nil
		},
		Execute: func(ctx context.Context) error {
			cfg, err := auth.LoadConfig()
			if err != nil || cfg.Host == "" {
				return fmt.Errorf("no host configured - complete the domain step first")
			}

			return auth.Login(ctx, cfg.Host)
		},
	}
}

// RepoStep detects the current git repository and displays the result.
func RepoStep() Step {
	return Step{
		Name: "Detect repository",
		Check: func(ctx context.Context) bool {
			return false // always show repo detection
		},
		Execute: func(ctx context.Context) error {
			repo := lib.DetectRepoFromGit()
			if repo == "" {
				fmt.Println("  No git repository detected. You can specify --repo when running commands.")
				return nil
			}

			fmt.Printf("  Detected repository: %s\n", repo)
			return nil
		},
	}
}

// MCPConfigStep detects AI tools and generates MCP configuration files.
func MCPConfigStep() Step {
	return Step{
		Name: "Configure MCP for AI tools",
		Check: func(ctx context.Context) bool {
			return false // always offer to configure
		},
		Execute: func(ctx context.Context) error {
			configured := false

			projectRoot, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("failed to get working directory: %w", err)
			}

			// Check for Cursor
			cursorDir := filepath.Join(projectRoot, ".cursor")
			if _, err := os.Stat(cursorDir); err == nil {
				cursorConfig := filepath.Join(cursorDir, "mcp.json")
				if err := writeMCPConfig(cursorConfig); err != nil {
					logger.L(ctx).Warn("failed to write Cursor MCP config", logger.Err(err))
				} else {
					fmt.Printf("  Configured MCP for Cursor (%s)\n", cursorConfig)
					configured = true
				}
			}

			// Check for Claude Code
			home, _ := os.UserHomeDir()
			claudeDir := filepath.Join(home, ".claude")
			if _, err := os.Stat(claudeDir); err == nil {
				configPath := filepath.Join(claudeDir, "mcp.json")
				if err := writeMCPConfig(configPath); err != nil {
					logger.L(ctx).Warn("failed to write Claude MCP config", logger.Err(err))
				} else {
					fmt.Printf("  Configured MCP for Claude Code (%s)\n", configPath)
					configured = true
				}
			}

			// Check for VS Code
			vscodeDir := filepath.Join(projectRoot, ".vscode")
			if _, err := os.Stat(vscodeDir); err == nil {
				vscodeConfig := filepath.Join(vscodeDir, "mcp.json")
				if err := writeMCPConfig(vscodeConfig); err != nil {
					logger.L(ctx).Warn("failed to write VS Code MCP config", logger.Err(err))
				} else {
					fmt.Printf("  Configured MCP for VS Code (%s)\n", vscodeConfig)
					configured = true
				}
			}

			if !configured {
				fmt.Println("  No AI tools detected. You can manually configure MCP by running 'nullify mcp serve'.")
			}

			return nil
		},
	}
}

// mcpConfig is the structure for MCP configuration files.
type mcpConfig struct {
	MCPServers map[string]mcpServerConfig `json:"mcpServers"`
}

type mcpServerConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func writeMCPConfig(path string) error {
	// Read existing config if present
	existing := mcpConfig{MCPServers: make(map[string]mcpServerConfig)}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &existing)
	}

	// Only add nullify if not already configured
	if _, ok := existing.MCPServers["nullify"]; ok {
		return nil
	}

	existing.MCPServers["nullify"] = mcpServerConfig{
		Command: "nullify",
		Args:    []string{"mcp", "serve"},
	}

	data, err := json.MarshalIndent(existing, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	return os.WriteFile(path, append(data, '\n'), 0600)
}

// SummaryStep reads host/token from config at execution time and displays next steps.
func SummaryStep() Step {
	return Step{
		Name: "Security posture summary",
		Check: func(ctx context.Context) bool {
			return false
		},
		Execute: func(ctx context.Context) error {
			cfg, err := auth.LoadConfig()
			if err != nil || cfg.Host == "" {
				fmt.Println("  Skipped - no host configured.")
				return nil
			}

			_, err = auth.GetValidToken(ctx, cfg.Host)
			if err != nil {
				fmt.Println("  Skipped - authentication required to fetch security posture.")
				return nil
			}

			fmt.Println("  Setup complete! Run 'nullify status' to view your security posture.")
			return nil
		},
	}
}
