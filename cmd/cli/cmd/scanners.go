package cmd

import (
	"context"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/findings"
)

// scannerEndpoint represents a scanner type and how to query it. An entry reads
// its API path, or the unified findings search when apiTypes is set.
type scannerEndpoint struct {
	name     string
	path     string
	apiTypes []string
}

// allScannerEndpoints returns the canonical list of all scanner endpoints.
func allScannerEndpoints() []scannerEndpoint {
	return []scannerEndpoint{
		{name: "sast", path: "/sast/findings"},
		{name: "sca_dependencies", path: "/sca/dependencies/findings"},
		{name: "sca_containers", path: "/sca/containers/findings"},
		{name: "secrets", path: "/secrets/findings"},
		{name: "pentest", path: "/dast/pentest/findings"},
		{name: "bughunt", path: "/dast/bughunt/findings"},
		{name: "cspm", path: "/cspm/findings"},
	}
}

// gateEndpoints returns what ci gate checks. With no type, or an unknown type, it
// is the default set. scpm and sensitive data need an explicit --type, so that
// existing users of ci gate do not start to fail on them. The second result reports
// an unknown type.
func gateEndpoints(findingType string) ([]scannerEndpoint, bool) {
	if findingType == "" {
		return allScannerEndpoints(), false
	}

	selectable := append(allScannerEndpoints(),
		scannerEndpoint{name: "scpm", apiTypes: findings.Types["scpm"].APITypes},
		scannerEndpoint{name: "secrets_sensitive_data", apiTypes: findings.Types["secrets_sensitive_data"].APITypes},
	)
	if filtered := filterEndpointsByType(selectable, findingType); filtered != nil {
		return filtered, false
	}
	return allScannerEndpoints(), true
}

// unifiedFindingsCount counts open findings with the unified search. The list routes
// of scpm and sensitive data have no status or repository filter.
func unifiedFindingsCount(ctx context.Context, c *api.Client, ep scannerEndpoint, severity, repo string) (int, error) {
	result, err := findings.Search(ctx, c, findings.SearchOptions{
		APITypes:   ep.apiTypes,
		Severity:   severity,
		Status:     "open",
		Repository: repo,
		Limit:      1,
	})
	return result.Total, err
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
