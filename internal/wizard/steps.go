package wizard

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/terminal"
)

func stdinIsTTY() bool {
	return terminal.IsInteractive(os.Stdin)
}

// DomainStep checks if a valid host is configured and prompts the user if not.
func DomainStep() Step {
	return Step{
		Name: "Configure Nullify domain",
		Check: func(ctx context.Context) bool {
			cfg, err := auth.LoadConfig()
			return err == nil && cfg.Host != ""
		},
		Execute: func(ctx context.Context) error {
			if !stdinIsTTY() {
				return fmt.Errorf("not a terminal; configure a host non-interactively with 'nullify auth login'")
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("  Enter your Nullify customer name (e.g., 'acme'), or press Enter to sign in through nullify.ai: ")
			input, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read input: %w", err)
			}

			host, err := domainFromInput(input)
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

func domainFromInput(input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" || auth.IsRouterHost(input) {
		return auth.RouterHost, nil
	}
	return lib.ParseCustomerDomain(input)
}

// AuthStep checks if a usable session exists and runs login if not.
func AuthStep() Step {
	return Step{
		Name: "Authenticate with Nullify",
		Check: func(ctx context.Context) bool {
			cfg, err := auth.LoadConfig()
			if err != nil || cfg.Host == "" {
				return false
			}
			return auth.CheckSession(ctx, cfg.Host) == nil
		},
		Execute: func(ctx context.Context) error {
			cfg, err := auth.LoadConfig()
			if err != nil || cfg.Host == "" {
				return fmt.Errorf("no host configured - complete the domain step first")
			}

			return auth.Login(ctx, cfg.Host, auth.InstallationPicker{
				Interactive: stdinIsTTY(),
				In:          os.Stdin,
				Out:         os.Stdout,
			})
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

// MCPConfigStep detects AI tools and adds the nullify MCP server to the config
// that each one reads.
func MCPConfigStep() Step {
	return Step{
		Name: "Configure MCP for AI tools",
		Check: func(ctx context.Context) bool {
			return false // always offer to configure
		},
		Execute: func(ctx context.Context) error {
			env, err := systemMCPEnv()
			if err != nil {
				return err
			}
			configureMCPClients(ctx, os.Stdout, env)
			return nil
		},
	}
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

			if err := auth.CheckSession(ctx, cfg.Host); err != nil {
				fmt.Println("  Skipped - authentication required to fetch security posture.")
				return nil
			}

			fmt.Println("  Setup complete! Run 'nullify status' to view your security posture.")
			return nil
		},
	}
}
