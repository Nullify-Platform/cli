package cmd

// scannerEndpoint represents a scanner type and its API path.
type scannerEndpoint struct {
	name string
	path string
}

// allScannerEndpoints returns the canonical list of all scanner endpoints.
func allScannerEndpoints() []scannerEndpoint {
	return []scannerEndpoint{
		{"sast", "/sast/findings"},
		{"sca_dependencies", "/sca/dependencies/findings"},
		{"sca_containers", "/sca/containers/findings"},
		{"secrets", "/secrets/findings"},
		{"pentest", "/dast/pentest/findings"},
		{"bughunt", "/dast/bughunt/findings"},
		{"cspm", "/cspm/findings"},
	}
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
