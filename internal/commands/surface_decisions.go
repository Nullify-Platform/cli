package commands

// Decisions is the record of command surface changes for this CLI. Every row
// has passed review. The evidence for a removal names the monorepo change that
// took the route away.
var Decisions = SurfaceDecisions{
	Moved: []MovedCommand{
		{From: "nullify api asset-graph list-reachability", To: "nullify api context list-reachability"},
		{From: "nullify api asset-graph list-search", To: "nullify api context list-search"},
		{From: "nullify api asset-graph list-subgraph", To: "nullify api context list-subgraph"},
		{From: "nullify api asset-graph list-summary", To: "nullify api context list-asset-graph-summary"},
		{From: "nullify api infrastructure list-graphs", To: "nullify api context list-graphs"},
		{From: "nullify api infrastructure list-info", To: "nullify api context list-info"},
		{From: "nullify api infrastructure list-summary", To: "nullify api context list-infrastructure-graphs-summary"},
		{From: "nullify api infrastructure get-graphs", To: "nullify api context get-graphs"},
		{From: "nullify api infrastructure get-download", To: "nullify api context get-download"},
		{From: "nullify api infrastructure get-graphs-versions", To: "nullify api context get-infrastructure-graphs-versions"},
		{From: "nullify api infrastructure get-graphs-versions-2", To: "nullify api context get-infrastructure-graphs-versions-2"},
	},
	RemovedCommands: []RemovedCommand{
		{Command: "nullify api admin create-initialize", Route: "POST /admin/repositories/initialize", Evidence: "#15172 deleted legacy repository enrollment; use update-repositories-scan-scope"},
		{Command: "nullify api admin create-uninitialize", Route: "POST /admin/repositories/uninitialize", Evidence: "#15172 deleted legacy repository enrollment; use update-repositories-scan-scope"},
		{Command: "nullify api context list-cloud-accounts", Route: "GET /context/asset-inventory/cloud-accounts", Evidence: "#2758 replaced this with per-category inventory (nullify api context list-asset-inventory), with a different response"},
		{Command: "nullify api context list-cloud-resources", Route: "GET /context/asset-inventory/cloud-resources", Evidence: "#2758 replaced this with list-asset-inventory, with a different response"},
		{Command: "nullify api context list-public-facing", Route: "GET /context/asset-inventory/public-facing", Evidence: "#2758 replaced this with list-public, with a different response"},
		{Command: "nullify api context list-resources", Route: "GET /context/asset-inventory/resources", Evidence: "#2758 replaced this with list-asset-inventory, with a different response"},
		{Command: "nullify api cspm get-diff", Route: "GET /cspm/findings/{findingId}/autofix/cache/diff", Evidence: "#12577 removed the CSPM fix cache; use get-state"},
		{Command: "nullify api manager create-credits", Route: "POST /manager/credits", Evidence: "#13015 removed the legacy credits system"},
		{Command: "nullify api manager list-credits", Route: "GET /manager/credits", Evidence: "#13015 removed the legacy credits system"},
		{Command: "nullify api manager delete-customer-questions", Route: "DELETE /manager/customer-questions", Evidence: "#5596 replaced customer questions with action items; use list-action-items"},
		{Command: "nullify api manager delete-customer-questions-2", Route: "DELETE /manager/customer-questions/{questionSetId}", Evidence: "#5596 replaced customer questions with action items; use list-action-items"},
		{Command: "nullify api manager delete-questions", Route: "DELETE /manager/customer-questions/{questionSetId}/questions/{questionId}", Evidence: "#5596 replaced customer questions with action items; use list-action-items"},
		{Command: "nullify api manager get-customer-questions", Route: "GET /manager/customer-questions/{questionSetId}", Evidence: "#5596 replaced customer questions with action items; use list-action-items"},
		{Command: "nullify api manager list-customer-questions", Route: "GET /manager/customer-questions", Evidence: "#5596 replaced customer questions with action items; use list-action-items"},
		{Command: "nullify api manager patch-answers", Route: "PATCH /manager/customer-questions/{questionSetId}/answers/{questionId}", Evidence: "#5596 replaced customer questions with action items; use list-action-items"},
		{Command: "nullify api manager list-escalations", Route: "GET /manager/escalations", Evidence: "#5596 replaced escalations with action items; use list-action-items"},
		{Command: "nullify api manager patch-escalations", Route: "PATCH /manager/escalations/{escalationId}", Evidence: "#5596 replaced escalations with action items; use list-action-items"},
		{Command: "nullify api orchestrator create-complete", Route: "POST /orchestrator/onboarding/complete", Evidence: "the route registers only when running locally, so it can only 404 in a deployed stack"},
		{Command: "nullify api sca get-sbom", Route: "GET /sca/repositories/{repositoryId}/sbom", Evidence: "#13504 moved SBOMs to context; use nullify sbom get or nullify api context get-sboms-repository-latest"},
		{Command: "nullify api scpm create-cache-by-id", Route: "POST /scpm/findings/{findingId}/autofix/cache", Evidence: "#12580 retired the SCPM fix cache"},
		{Command: "nullify api scpm create-create_pr-by-id", Route: "POST /scpm/findings/{findingId}/autofix/cache/create_pr", Evidence: "#12580 retired the SCPM fix cache"},
		{Command: "nullify api scpm get-diff", Route: "GET /scpm/findings/{findingId}/autofix/cache/diff", Evidence: "#12580 retired the SCPM fix cache; use get-state"},
		{Command: "nullify api scpm create-retriage", Route: "POST /scpm/findings/retriage", Evidence: "#5479 moved retriage to orchestrator create-retriage, with a different request body"},
		{Command: "nullify api scpm list-dependencies", Route: "GET /scpm/dependencies", Evidence: "#13491 cut the SCPM schema to the SAST shape; use create-dependencies-analyze or create-batch"},
		{Command: "nullify pentest get-pentest-findings-autofix-cache-diff", Route: "GET /dast/pentest/findings/{findingId}/autofix/cache/diff", Evidence: "#12688 removed retired DAST previews; use get-state"},
	},
	RetiredFlags: []RetiredFlag{
		{Command: "nullify api asset-graph list-reachability", Flag: "account-id", Evidence: "GET /context/asset-graph/reachability has no account filter; the flag has no effect"},
		{Command: "nullify api asset-graph list-subgraph", Flag: "account-id", Evidence: "GET /context/asset-graph/subgraph has no account filter; the flag has no effect"},
		{Command: "nullify api cspm list-scans", Flag: "region", Evidence: "GET /cspm/scans no longer filters by region; the flag has no effect"},
		{Command: "nullify api cspm list-scans", Flag: "scan-type", Evidence: "GET /cspm/scans no longer filters by scan type; the flag has no effect"},
	},
}
