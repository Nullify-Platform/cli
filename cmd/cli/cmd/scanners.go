package cmd

// findingTypeToAPI maps CLI type slugs to the API's FindingType values.
// The unified /admin/findings endpoint uses PascalCase type names.
var findingTypeToAPI = map[string]string{
	"sast":             "Code",
	"sca_dependencies": "Dependencies",
	"sca_containers":   "Containers",
	"secrets":          "Secrets",
	"pentest":          "Pentest",
	"bughunt":          "BugHunting",
	"cspm":             "Cloud",
}

// scannerEndpoint represents a scanner type, its API path, and the server-side
// filters that endpoint implements. An unimplemented query parameter is dropped
// without error, so a gate that sends one reports a filter it never applied.
type scannerEndpoint struct {
	name               string
	path               string
	supportsSeverity   bool
	supportsIsResolved bool
}

// allScannerEndpoints returns the canonical list of all scanner endpoints.
//
// Only /sast/findings and /cspm/findings implement a severity filter. Every
// endpoint except /cspm/findings and /dast/bughunt/findings implements
// isResolved: /cspm/findings declares a status parameter its handler never
// copies into CSPMFindingFilters, and /dast/bughunt/findings takes no filters.
func allScannerEndpoints() []scannerEndpoint {
	return []scannerEndpoint{
		{name: "sast", path: "/sast/findings", supportsSeverity: true, supportsIsResolved: true},
		{name: "sca_dependencies", path: "/sca/dependencies/findings", supportsIsResolved: true},
		{name: "sca_containers", path: "/sca/containers/findings", supportsIsResolved: true},
		{name: "secrets", path: "/secrets/findings", supportsIsResolved: true},
		{name: "pentest", path: "/dast/pentest/findings", supportsIsResolved: true},
		{name: "bughunt", path: "/dast/bughunt/findings"},
		{name: "cspm", path: "/cspm/findings", supportsSeverity: true},
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
