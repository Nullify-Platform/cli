package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate shell completion scripts",
	Long: `Generate shell completion scripts for the Nullify CLI.

To load completions:

Bash:
  $ source <(nullify completion bash)
  # To load completions for each session, execute once:
  # Linux:
  $ nullify completion bash > /etc/bash_completion.d/nullify
  # macOS:
  $ nullify completion bash > $(brew --prefix)/etc/bash_completion.d/nullify

Zsh:
  $ source <(nullify completion zsh)
  # To load completions for each session, execute once:
  $ nullify completion zsh > "${fpath[1]}/_nullify"

Fish:
  $ nullify completion fish | source
  # To load completions for each session, execute once:
  $ nullify completion fish > ~/.config/fish/completions/nullify.fish

PowerShell:
  PS> nullify completion powershell | Out-String | Invoke-Expression
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run: func(cmd *cobra.Command, args []string) {
		switch args[0] {
		case "bash":
			rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
