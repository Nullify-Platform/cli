package cmd

import (
	"context"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/findings"
)

// scannerEndpoint represents a scanner type and how to query it. ci gate reads the
// unified findings search with apiTypes. ci report and status read the list route
// at path.
type scannerEndpoint struct {
	name     string
	path     string
	apiTypes []string
}

// allScannerEndpoints returns the canonical list of all scanner endpoints.
func allScannerEndpoints() []scannerEndpoint {
	return []scannerEndpoint{
		{name: "sast", path: "/sast/findings", apiTypes: findings.Types["sast"].APITypes},
		{name: "sca_dependencies", path: "/sca/dependencies/findings", apiTypes: findings.Types["sca_dependencies"].APITypes},
		{name: "sca_containers", path: "/sca/containers/findings", apiTypes: findings.Types["sca_containers"].APITypes},
		{name: "secrets", path: "/secrets/findings", apiTypes: []string{"SecretsCredentials"}},
		{name: "pentest", path: "/dast/pentest/findings", apiTypes: findings.Types["pentest"].APITypes},
		{name: "bughunt", path: "/dast/bughunt/findings", apiTypes: findings.Types["bughunt"].APITypes},
		{name: "cspm", path: "/cspm/findings", apiTypes: findings.Types["cspm"].APITypes},
	}
}

// gateEndpoints returns what ci gate checks. With no type, or an unknown type, it
// is the default set. A named type uses the names that the findings commands accept.
// scpm and sensitive data need an explicit --type, so that existing users of ci gate
// do not start to fail on them. The second result reports an unknown type.
func gateEndpoints(findingType string) ([]scannerEndpoint, bool) {
	defaults := allScannerEndpoints()
	if findingType == "" {
		return defaults, false
	}

	if filtered := filterEndpointsByType(defaults, findingType); filtered != nil {
		return filtered, false
	}

	apiTypes, err := findings.APITypesFor(findingType)
	if err != nil {
		return defaults, true
	}
	return []scannerEndpoint{{name: findingType, apiTypes: apiTypes}}, false
}

// unifiedFindingsCount counts the open findings of an endpoint with the unified
// search. The list routes do not read a status or repository filter. Findings with
// no repository are counted across the tenant, because a repository filter would
// always pass them. A row without a total still counts, so that a response in a
// changed shape cannot pass a gate.
func unifiedFindingsCount(ctx context.Context, c *api.Client, ep scannerEndpoint, severity, repo string) (int, error) {
	opts := findings.SearchOptions{APITypes: ep.apiTypes, Severity: severity, Status: "open", Limit: 1}
	if findings.HasRepository(ep.apiTypes) {
		opts.Repository = repo
	}

	result, err := findings.Search(ctx, c, opts)
	return max(result.Total, result.Returned), err
}

// filterEndpointsByType returns only endpoints matching the given type name.
// Returns nil if no match is found.
func filterEndpointsByType(endpoints []scannerEndpoint, typeName string) []scannerEndpoint {
	var filtered []scannerEndpoint
	for _, ep := range endpoints {
		if ep.name == typeName {
			filtered = append(filtered, ep)
		}
	}
	return filtered
}
