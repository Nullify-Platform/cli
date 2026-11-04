package auth

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/api/models"
	"github.com/nullify-platform/cli/internal/logger"
)

var errNoUsableInstallation = errors.New("no installation is ready for CLI access through nullify.ai - run 'nullify auth login --host <instance>.nullify.ai' with your Nullify instance")

// Installation is a tenant installation that the router can route the user to.
type Installation struct {
	Name            string
	DataHost        string
	QueryParameters map[string]string
}

// InstallationPicker selects one installation by name, by prompt, or automatically when only one exists.
type InstallationPicker struct {
	Name        string
	Interactive bool
	In          io.Reader
	Out         io.Writer
}

func fetchInstallations(ctx context.Context, token string) ([]Installation, error) {
	client := api.NewClient(RouterHost, token, nil, api.WithHTTPClient(httpClient))
	client.BaseURL = authBaseURL(RouterHost)

	out, err := client.ListAdminInstallations(ctx, api.ListAdminInstallationsInput{})
	if err != nil {
		return nil, fmt.Errorf("list installations: %w", err)
	}
	return usableInstallations(ctx, out.Installations), nil
}

func usableInstallations(ctx context.Context, outputs []models.EndpointsAdminInstallationOutput) []Installation {
	installs := make([]Installation, 0, len(outputs))
	for _, out := range outputs {
		if out.NullifyBaseURL == nil {
			logger.L(ctx).Debug("skipping installation without a base url", logger.String("installation", out.Name))
			continue
		}
		if len(out.QueryParameters) == 0 {
			logger.L(ctx).Debug("skipping installation without query parameters", logger.String("installation", out.Name))
			continue
		}

		dataHost, err := dataHostFromBaseURL(*out.NullifyBaseURL)
		if err != nil {
			logger.L(ctx).Debug("skipping installation with invalid base url", logger.String("installation", out.Name), logger.Err(err))
			continue
		}

		installs = append(installs, Installation{
			Name:            out.Name,
			DataHost:        dataHost,
			QueryParameters: maps.Clone(out.QueryParameters),
		})
	}
	return installs
}

// Pick returns the selected installation from installs.
func (p InstallationPicker) Pick(installs []Installation) (Installation, error) {
	if len(installs) == 0 {
		return Installation{}, errNoUsableInstallation
	}

	if p.Name != "" {
		return findInstallation(installs, p.Name)
	}

	if len(installs) == 1 {
		return installs[0], nil
	}

	if !p.Interactive {
		return Installation{}, fmt.Errorf("multiple installations are available (%s) - pass --installation <name>", installationNames(installs))
	}
	return p.prompt(installs)
}

func findInstallation(installs []Installation, name string) (Installation, error) {
	var matches []Installation
	for _, install := range installs {
		if install.Name == name {
			matches = append(matches, install)
		}
	}

	switch len(matches) {
	case 0:
		return Installation{}, fmt.Errorf("installation %q not found - available: %s", name, installationNames(installs))
	case 1:
		return matches[0], nil
	default:
		return Installation{}, fmt.Errorf("installation name %q matches %d installations - run 'nullify auth login --host <instance>.nullify.ai'", name, len(matches))
	}
}

func (p InstallationPicker) prompt(installs []Installation) (Installation, error) {
	if err := ensureUniqueNames(installs); err != nil {
		return Installation{}, err
	}

	fmt.Fprintln(p.Out, "Select an installation:")
	for i, install := range installs {
		fmt.Fprintf(p.Out, "  %d) %s (%s)\n", i+1, install.Name, install.DataHost)
	}
	fmt.Fprintf(p.Out, "Enter a number [1-%d]: ", len(installs))

	line, err := bufio.NewReader(p.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return Installation{}, fmt.Errorf("read selection: %w", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(installs) {
		return Installation{}, fmt.Errorf("invalid selection %q - enter a number from 1 to %d", strings.TrimSpace(line), len(installs))
	}
	return installs[choice-1], nil
}

func ensureUniqueNames(installs []Installation) error {
	seen := make(map[string]bool, len(installs))
	for _, install := range installs {
		if seen[install.Name] {
			return fmt.Errorf("installation name %q is used by more than one installation - run 'nullify auth login --host <instance>.nullify.ai'", install.Name)
		}
		seen[install.Name] = true
	}
	return nil
}

func installationNames(installs []Installation) string {
	names := make([]string, 0, len(installs))
	for _, install := range installs {
		names = append(names, install.Name)
	}
	return strings.Join(names, ", ")
}
