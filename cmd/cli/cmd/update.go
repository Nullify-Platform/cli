package cmd

import (
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/google/go-github/v85/github"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/spf13/cobra"
)

const (
	releaseRepoOwner = "Nullify-Platform"
	releaseRepoName  = "cli"
	releasesURL      = "https://github.com/Nullify-Platform/cli/releases"
	installScriptURL = "https://raw.githubusercontent.com/Nullify-Platform/cli/main/install.sh"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for CLI updates",
	Long: "Check GitHub for the latest Nullify CLI release and print the commands " +
		"that install it. The command does not change the installed binary.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ghClient := github.NewClient(nil)
		release, _, err := ghClient.Repositories.GetLatestRelease(
			cmd.Context(), releaseRepoOwner, releaseRepoName)
		if err != nil {
			return fmt.Errorf("checking for updates: %w", err)
		}
		return writeUpdateAdvice(cmd.OutOrStdout(), logger.Version,
			release.GetTagName(), runtime.GOOS, runtime.GOARCH)
	},
}

// writeUpdateAdvice compares the running version with the latest release tag
// and, when an upgrade applies, prints how to install that release on
// goos/goarch. A version that is not a release, such as "dev" or a commit,
// is a development build.
func writeUpdateAdvice(w io.Writer, current, latestTag, goos, goarch string) error {
	latest, ok := parseSemver(latestTag)
	if !ok {
		return fmt.Errorf("the latest release has an unexpected tag %q", latestTag)
	}
	latestVersion := strings.TrimPrefix(latestTag, "v")

	running, ok := parseSemver(current)
	switch {
	case !ok:
		fmt.Fprintf(w, "You are running a development build (%s). The latest release is %s.\n\n",
			displayVersion(current), latestVersion)
	case compareSemver(running, latest) == 0:
		fmt.Fprintf(w, "You are running the latest version (%s)\n", current)
		return nil
	case compareSemver(running, latest) > 0:
		fmt.Fprintf(w, "You are running %s, which is newer than the latest release (%s).\n",
			current, latestVersion)
		return nil
	default:
		fmt.Fprintf(w, "A new version is available: %s (current: %s)\n\n", latestVersion, current)
	}

	writeUpgradeSteps(w, latestTag, goos, goarch)
	return nil
}

func displayVersion(v string) string {
	if v == "" {
		return "unknown"
	}
	return v
}

// writeUpgradeSteps prints how to install the release tagged tag. Releases
// exist for macOS and Linux on amd64 and arm64, and for Windows on amd64,
// which Windows on Arm runs too.
func writeUpgradeSteps(w io.Writer, tag, goos, goarch string) {
	installer := fmt.Sprintf("curl -sSfL %s | sh -s -- --version %s", installScriptURL, tag)
	hasBuild := goarch == "amd64" || goarch == "arm64"

	switch {
	case hasBuild && (goos == "darwin" || goos == "linux"):
		fmt.Fprintf(w, "Install it with the installer:\n\n  %s\n\n", installer)
		fmt.Fprintln(w, "It replaces nullify in /usr/local/bin when that is writable, otherwise in ~/.local/bin.")
	case hasBuild && goos == "windows":
		writeWindowsUpgradeSteps(w, tag, installer)
	default:
		fmt.Fprintf(w, "There is no release build for %s/%s. See %s/tag/%s.\n",
			goos, goarch, releasesURL, tag)
	}
}

func writeWindowsUpgradeSteps(w io.Writer, tag, installer string) {
	download := fmt.Sprintf("%s/download/%s", releasesURL, tag)
	dir := "nullify-" + tag

	fmt.Fprintf(w, "Install it in PowerShell:\n\n")
	fmt.Fprintf(w, "  Invoke-WebRequest %s/nullify_windows_amd64.zip -OutFile nullify.zip\n", download)
	fmt.Fprintf(w, "  Expand-Archive nullify.zip -DestinationPath %s\n\n", dir)
	fmt.Fprintf(w, "Check that (Get-FileHash nullify.zip).Hash matches, ignoring case, the\n")
	fmt.Fprintf(w, "nullify_windows_amd64.zip line of %s/checksums.txt.\n", download)
	fmt.Fprintf(w, "Then replace the nullify.exe on your PATH with %s\\nullify.exe.\n\n", dir)
	fmt.Fprintf(w, "Or install it in Git Bash:\n\n  %s\n", installer)
}

func init() {
	rootCmd.AddCommand(updateCmd)
}
