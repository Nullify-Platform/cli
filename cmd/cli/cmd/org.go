package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/nullify-platform/cli/internal/auth"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/output"
	"github.com/spf13/cobra"
)

// listOrgs, promptIn and promptOut are vars so tests can stand in for the
// router and the terminal.
var (
	listOrgs            = auth.ListOrgs
	promptIn  io.Reader = os.Stdin
	promptOut io.Writer = os.Stderr
)

// orgScope is the org a command runs as and the query parameters that say
// so. Org is nil when the scope is left to the server (an API token's own
// org) or given only as a raw id.
type orgScope struct {
	Org   *auth.Org
	Query map[string]string
}

// usesMachineToken reports whether the command authenticates with an API or
// GitHub Actions token rather than a browser login, in lib.GetNullifyToken's
// precedence. Such a token carries its own single org.
func usesMachineToken() bool {
	return nullifyToken != "" || os.Getenv("NULLIFY_TOKEN") != "" ||
		(os.Getenv("GITHUB_ACTIONS") == "true" && githubToken != "" && os.Getenv("GITHUB_REPOSITORY") != "")
}

// orgInputsFor gathers every way the current invocation can name its org on
// host. flag and source are --org, or a caller's equivalent.
func orgInputsFor(host, flag, source string) auth.OrgInputs {
	in := auth.OrgInputs{
		Flag:             flag,
		FlagSource:       source,
		EnvOrg:           os.Getenv("NULLIFY_ORG"),
		EnvGitHubOwnerID: os.Getenv("NULLIFY_GITHUB_OWNER_ID"),
		GitOwner:         lib.DetectOwnerFromGit(),
	}
	if hosts, err := auth.LoadHosts(); err == nil {
		in.Stored = hosts[auth.CredentialKey(host)].Org
	}
	return in
}

// resolveOrgScope picks the org a command on host runs as (auth.ResolveOrg).
// An API token names its org only when asked to: with no explicit choice
// the request goes without one and the server takes the token's own. When
// the choice is ambiguous and prompt is set, the user is asked and the
// answer is remembered for host.
func resolveOrgScope(ctx context.Context, host, token string, in auth.OrgInputs, prompt bool) (orgScope, error) {
	listHost := host
	if usesMachineToken() {
		if strings.TrimSpace(in.Flag) == "" && strings.TrimSpace(in.EnvOrg) == "" {
			if id := strings.TrimSpace(in.EnvGitHubOwnerID); id != "" {
				return orgScope{Query: map[string]string{"githubOwnerId": id}}, nil
			}
			return orgScope{Query: map[string]string{}}, nil
		}
		// The token is the tenant's, so its orgs are read from the tenant.
		in = auth.OrgInputs{Flag: in.Flag, FlagSource: in.FlagSource, EnvOrg: in.EnvOrg}
	} else {
		var err error
		if listHost, err = auth.AuthHostFor(host); err != nil {
			return orgScope{}, err
		}
	}

	list, err := listOrgsFresh(ctx, host, listHost, token)
	if err != nil {
		return orgScope{}, err
	}

	org, err := auth.ResolveOrg(host, list, in)
	var notChosen *auth.ErrOrgNotChosen
	if errors.As(err, &notChosen) && prompt && !usesMachineToken() {
		explicit := strings.TrimSpace(in.Flag) != "" || strings.TrimSpace(in.EnvOrg) != "" || strings.TrimSpace(in.EnvGitHubOwnerID) != ""
		org, err = promptForOrg(host, notChosen.Orgs)
		// An ambiguous --org answers this command only; the remembered pick
		// changes when nothing named an org.
		if err == nil && !explicit {
			if saveErr := rememberOrg(host, org); saveErr != nil {
				fmt.Fprintf(promptOut, "Could not remember %s for %s: %v\n", org.Name, host, saveErr)
			} else {
				fmt.Fprintf(promptOut, "Using %s on %s from now on; change it with 'nullify org use'.\n", org.Name, host)
			}
		}
	}
	if err != nil {
		return orgScope{}, err
	}
	return orgScope{Org: &org, Query: org.Query()}, nil
}

// listOrgsFresh lists orgs with token, and once more with a force-refreshed
// token if the list rejects it: a token can stop being accepted before its
// stored expiry, and the org list is often a command's first call.
func listOrgsFresh(ctx context.Context, host, listHost, token string) (auth.OrgList, error) {
	list, err := listOrgs(ctx, host, listHost, token)
	if !errors.Is(err, auth.ErrTokenRejected) {
		return list, err
	}
	fresh, refreshErr := lib.RefreshNullifyToken(ctx, host, nullifyToken, githubToken)
	if refreshErr != nil || fresh == "" || fresh == token {
		return list, err
	}
	return listOrgs(ctx, host, listHost, fresh)
}

func promptForOrg(host string, orgs []auth.Org) (auth.Org, error) {
	fmt.Fprintf(promptOut, "%s serves several of your organizations:\n", host)
	for i, o := range orgs {
		fmt.Fprintf(promptOut, "  %d) %s\n", i+1, o)
	}
	fmt.Fprint(promptOut, "Choose one (number or name): ")

	line, err := bufio.NewReader(promptIn).ReadString('\n')
	if err != nil && line == "" {
		return auth.Org{}, fmt.Errorf("no organization chosen: %w", err)
	}
	answer := strings.TrimSpace(line)
	if n, convErr := strconv.Atoi(answer); convErr == nil && n >= 1 && n <= len(orgs) {
		return orgs[n-1], nil
	}
	for _, o := range orgs {
		if o.Matches(answer) {
			return o, nil
		}
	}
	return auth.Org{}, fmt.Errorf("%q is not one of the listed organizations", answer)
}

func rememberOrg(host string, org auth.Org) error {
	return auth.UpdateHostConfig(host, func(hc auth.HostConfig) auth.HostConfig {
		hc.Org = &auth.OrgPick{Name: org.Name, Key: org.Key, ID: org.ID}
		return hc
	})
}

var orgCmd = &cobra.Command{
	Use:   "org",
	Short: "Choose the organization commands run as",
	Long: "A login can cover several organizations on one Nullify host. Commands run as the org chosen by " +
		"--org, NULLIFY_ORG, NULLIFY_GITHUB_OWNER_ID, 'nullify org use', the git remote's owner, or the only org, in that order.",
}

var orgListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the organizations you can use on this host",
	Long: "List the organizations your login can use on this host, those not routed to a host yet, and those on " +
		"other hosts. \"selected\" is the organization a command run now would use (--org changes it), and " +
		"\"selection\" says why none is when that is the case.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		authCtx, err := resolveCommandToken(ctx)
		if err != nil {
			return err
		}

		out, err := orgListing(ctx, authCtx.Host, authCtx.Token, orgFlag)
		if err != nil {
			return err
		}

		data, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		return output.Print(cmd, data)
	},
}

var orgUseCmd = &cobra.Command{
	Use:   "use <name|id>",
	Short: "Remember the organization to use on this host",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if usesMachineToken() {
			return fmt.Errorf("an API token carries its own organization; 'nullify org use' applies to 'nullify auth login' sessions")
		}
		authCtx, err := resolveCommandToken(ctx)
		if err != nil {
			return err
		}

		listHost, err := auth.AuthHostFor(authCtx.Host)
		if err != nil {
			return err
		}
		list, err := listOrgsFresh(ctx, authCtx.Host, listHost, authCtx.Token)
		if err != nil {
			return err
		}
		org, err := auth.ResolveOrg(authCtx.Host, list, auth.OrgInputs{Flag: args[0], FlagSource: "org"})
		if err != nil {
			return err
		}
		if err := rememberOrg(authCtx.Host, org); err != nil {
			return fmt.Errorf("failed to save the organization: %w", err)
		}

		fmt.Printf("Using %s on %s\n", org, authCtx.Host)
		return nil
	},
}

// orgListing describes the orgs the token can use on host and which one a
// call naming none would run as, for `nullify org list` and the MCP
// list_organizations tool. flag is --org.
func orgListing(ctx context.Context, host, token, flag string) (map[string]any, error) {
	listHost := host
	if !usesMachineToken() {
		var err error
		if listHost, err = auth.AuthHostFor(host); err != nil {
			return nil, err
		}
	}
	list, err := listOrgsFresh(ctx, host, listHost, token)
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"host":          host,
		"organizations": nonNil(list.Orgs),
	}
	if len(list.Pending) > 0 {
		out["pending"] = list.Pending
	}
	if len(list.Elsewhere) > 0 {
		out["elsewhere"] = list.Elsewhere
	}
	scope, err := resolveOrgScope(ctx, host, token, orgInputsFor(host, flag, "--org"), false)
	switch {
	case err != nil:
		out["selected"] = nil
		out["selection"] = err.Error()
	case scope.Org != nil:
		out["selected"] = scope.Org.Name
	case scope.Query["githubOwnerId"] != "":
		out["selected"] = nil
		out["selection"] = "githubOwnerId " + scope.Query["githubOwnerId"] + " (NULLIFY_GITHUB_OWNER_ID)"
	default:
		out["selected"] = nil
		out["selection"] = "the API token's own organization"
	}
	return out, nil
}

func nonNil(orgs []auth.Org) []auth.Org {
	if orgs == nil {
		return []auth.Org{}
	}
	return orgs
}

func init() {
	rootCmd.AddCommand(orgCmd)
	orgCmd.AddCommand(orgListCmd)
	orgCmd.AddCommand(orgUseCmd)
}
