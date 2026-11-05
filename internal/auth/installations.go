package auth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var errNoUsableInstallation = errors.New("none of your organizations is ready for CLI access through the Nullify router - if your instance signs in itself, run 'nullify auth login --host <instance>.nullify.ai'")

// InstallationPicker selects the org a router login starts with: by name or
// id, the one remembered for its host, by prompt, or the only one.
type InstallationPicker struct {
	Name        string
	Interactive bool
	In          io.Reader
	Out         io.Writer
	// Remembered is the org last chosen, used when it is still offered.
	Remembered *OrgPick
}

// routedOrgs returns the orgs a router serves from a usable data host.
func routedOrgs(orgs []Org) []Org {
	routed := make([]Org, 0, len(orgs))
	for _, o := range orgs {
		if o.Host != "" && o.Status != "pending" && o.Status != "unavailable" {
			routed = append(routed, o)
		}
	}
	return routed
}

func orgsOn(orgs []Org, dataHost string) []Org {
	on := make([]Org, 0, len(orgs))
	for _, o := range orgs {
		if o.DataHost() == CredentialKey(dataHost) {
			on = append(on, o)
		}
	}
	return on
}

// Pick returns the selected org from orgs.
func (p InstallationPicker) Pick(orgs []Org) (Org, error) {
	if len(orgs) == 0 {
		return Org{}, errNoUsableInstallation
	}

	if p.Name != "" {
		return findInstallation(orgs, p.Name)
	}

	if p.Remembered != nil {
		for _, o := range orgs {
			if o.Key == p.Remembered.Key && o.ID == p.Remembered.ID {
				return o, nil
			}
		}
	}

	if len(orgs) == 1 {
		return orgs[0], nil
	}

	if !p.Interactive {
		return Org{}, fmt.Errorf("multiple organizations are available (%s) - pass --org <name>", installationNames(orgs))
	}
	return p.prompt(orgs)
}

func findInstallation(orgs []Org, name string) (Org, error) {
	var matches []Org
	for _, o := range orgs {
		if o.Matches(name) {
			matches = append(matches, o)
		}
	}

	switch len(matches) {
	case 0:
		return Org{}, fmt.Errorf("organization %q not found - available: %s", name, installationNames(orgs))
	case 1:
		return matches[0], nil
	default:
		return Org{}, fmt.Errorf("organization name %q matches %d organizations - use its id", name, len(matches))
	}
}

func (p InstallationPicker) prompt(orgs []Org) (Org, error) {
	fmt.Fprintln(p.Out, "Select an organization:")
	for i, o := range orgs {
		fmt.Fprintf(p.Out, "  %d) %s on %s\n", i+1, o, o.DataHost())
	}
	fmt.Fprintf(p.Out, "Enter a number [1-%d]: ", len(orgs))

	line, err := bufio.NewReader(p.In).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return Org{}, fmt.Errorf("read selection: %w", err)
	}

	choice, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || choice < 1 || choice > len(orgs) {
		return Org{}, fmt.Errorf("invalid selection %q - enter a number from 1 to %d", strings.TrimSpace(line), len(orgs))
	}
	return orgs[choice-1], nil
}

func installationNames(orgs []Org) string {
	names := make([]string, 0, len(orgs))
	for _, o := range orgs {
		names = append(names, o.Name)
	}
	return strings.Join(names, ", ")
}
