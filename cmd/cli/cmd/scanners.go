package cmd

type scannerEndpoint struct {
	name               string
	path               string
	supportsSeverity   bool
	supportsIsResolved bool
	supportsOpenStatus bool
}

func allScannerEndpoints() []scannerEndpoint {
	return []scannerEndpoint{
		{name: "sast", path: "/sast/findings", supportsSeverity: true, supportsIsResolved: true},
		{name: "sca_dependencies", path: "/sca/dependencies/findings", supportsIsResolved: true},
		{name: "sca_containers", path: "/sca/containers/findings", supportsIsResolved: true},
		{name: "secrets", path: "/secrets/findings", supportsIsResolved: true},
		{name: "pentest", path: "/dast/pentest/findings", supportsIsResolved: true},
		{name: "bughunt", path: "/dast/bughunt/findings"},
		{name: "cspm", path: "/cspm/findings", supportsSeverity: true, supportsOpenStatus: true},
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
