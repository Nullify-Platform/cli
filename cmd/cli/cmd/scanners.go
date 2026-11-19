package cmd

// scannerEndpoint describes one per-scanner finding list route and the
// filters it supports.
type scannerEndpoint struct {
	name               string
	path               string
	supportsSeverity   bool
	supportsIsResolved bool
	supportsOpenStatus bool
	// severityFields are the finding fields that hold its severity, in the
	// order they are read. The first non-empty one wins, so an override is
	// listed before the value it overrides. A scanner whose findings carry
	// no severity has none, and its findings count at every threshold.
	severityFields []string
	// filtersOpenOnClient marks a list route with no lifecycle filter. It
	// returns allowlisted, archived, false-positive and fixed findings
	// too, so the CLI drops them itself.
	filtersOpenOnClient bool
}

func allScannerEndpoints() []scannerEndpoint {
	return []scannerEndpoint{
		{name: "sast", path: "/sast/findings", supportsSeverity: true, supportsIsResolved: true, severityFields: []string{"severity"}},
		{name: "sca_dependencies", path: "/sca/dependencies/findings", supportsIsResolved: true, severityFields: []string{"vulnerabilitiesMaxSeverity"}},
		{name: "sca_containers", path: "/sca/containers/findings", supportsIsResolved: true, severityFields: []string{"vulnerabilitiesMaxSeverity"}},
		{name: "secrets", path: "/secrets/findings", supportsIsResolved: true},
		{name: "pentest", path: "/dast/pentest/findings", supportsIsResolved: true, severityFields: []string{"effectiveSeverity", "severity"}},
		{name: "bughunt", path: "/dast/bughunt/findings", filtersOpenOnClient: true, severityFields: []string{"severityOverride", "severity"}},
		{name: "cspm", path: "/cspm/findings", supportsSeverity: true, supportsOpenStatus: true, severityFields: []string{"severity"}},
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
