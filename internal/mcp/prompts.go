package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func promptResult(description, text string) *mcplib.GetPromptResult {
	return &mcplib.GetPromptResult{
		Description: description,
		Messages: []mcplib.PromptMessage{
			{
				Role:    mcplib.RoleUser,
				Content: mcplib.NewTextContent(text),
			},
		},
	}
}

func registerPrompts(s *server.MCPServer) {
	s.AddPrompt(
		mcplib.Prompt{
			Name:        "security-review",
			Description: "Review the security findings for this repository and recommend a prioritized remediation plan.",
			Arguments: []mcplib.PromptArgument{
				{
					Name:        "repository",
					Description: "The repository to review",
					Required:    false,
				},
			},
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			repo := request.Params.Arguments["repository"]
			prompt := "Review the security findings"
			if repo != "" {
				prompt += " for the " + repo + " repository"
			}
			prompt += " and recommend a prioritized remediation plan. Focus on critical and high severity findings first. For each finding, explain the risk, suggest a fix, and estimate the effort."

			return promptResult("Security review prompt", prompt), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "triage-finding",
			Description: "Analyze a finding and determine if it's a true positive, false positive, or accepted risk.",
			Arguments: []mcplib.PromptArgument{
				{
					Name:        "finding_id",
					Description: "The finding ID to triage",
					Required:    true,
				},
				{
					Name:        "finding_type",
					Description: "The type of finding (sast, sca, secrets, pentest)",
					Required:    true,
				},
			},
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			findingID := request.Params.Arguments["finding_id"]
			findingType := request.Params.Arguments["finding_type"]

			prompt := "Analyze the " + findingType + " finding with ID " + findingID + ". "
			prompt += "First, retrieve the finding details. Then determine if this is a true positive, false positive, or an accepted risk. "
			prompt += "Consider the code context, the vulnerability type, and whether there are mitigating controls. "
			prompt += "Provide your recommendation with a clear rationale."

			return promptResult("Finding triage prompt", prompt), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "explain-vulnerability",
			Description: "Explain a vulnerability in simple terms, its impact, and how to fix it.",
			Arguments: []mcplib.PromptArgument{
				{
					Name:        "finding_id",
					Description: "The finding ID to explain",
					Required:    true,
				},
				{
					Name:        "finding_type",
					Description: "The type of finding (sast, sca, secrets, pentest)",
					Required:    true,
				},
			},
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			findingID := request.Params.Arguments["finding_id"]
			findingType := request.Params.Arguments["finding_type"]

			prompt := "Explain the " + findingType + " finding with ID " + findingID + " in simple terms. "
			prompt += "First, retrieve the finding details. Then explain: "
			prompt += "1. What the vulnerability is (in non-technical language). "
			prompt += "2. What could happen if it's exploited (real-world impact). "
			prompt += "3. How to fix it (step-by-step). "
			prompt += "4. How to prevent similar issues in the future."

			return promptResult("Vulnerability explanation prompt", prompt), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "security-posture-overview",
			Description: "Get a comprehensive overview of the organization's security posture with trends.",
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			return promptResult(
				"Security posture overview",
				"First, call the get_security_posture_summary tool to get current finding counts across all scanner types. "+
					"Then call get_security_trends with period 30d to see how the posture has changed. "+
					"Summarize the overall security state, highlight areas of concern, and note any improving or worsening trends.",
			), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "investigate-repo",
			Description: "Deep-dive investigation of a specific repository's security findings.",
			Arguments: []mcplib.PromptArgument{
				{Name: "repository", Description: "The repository to investigate", Required: true},
			},
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			repo := request.Params.Arguments["repository"]
			return promptResult(
				"Repository investigation",
				"Investigate the security posture of the "+repo+" repository. "+
					"Call nullify_search_findings for each finding type (sast, sca_dependency, sca_container, secrets, pentest, bughunt, cspm) with repository="+repo+". "+
					"Summarize the findings by type and severity, identify the most critical issues, and recommend a prioritized remediation plan.",
			), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "remediation-plan",
			Description: "Create a prioritized remediation plan for a repository.",
			Arguments: []mcplib.PromptArgument{
				{Name: "repository", Description: "The repository to plan remediation for", Required: true},
			},
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			repo := request.Params.Arguments["repository"]
			return promptResult(
				"Remediation plan",
				"Create a prioritized remediation plan for the "+repo+" repository. "+
					"First, search for all critical and high severity findings using nullify_search_findings with repository="+repo+". "+
					"For each finding, assess the effort to fix and business impact. "+
					"Produce a prioritized list of actions with estimated effort and expected risk reduction.",
			), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "compare-repos",
			Description: "Compare the security posture of two repositories.",
			Arguments: []mcplib.PromptArgument{
				{Name: "repo1", Description: "First repository", Required: true},
				{Name: "repo2", Description: "Second repository", Required: true},
			},
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			repo1 := request.Params.Arguments["repo1"]
			repo2 := request.Params.Arguments["repo2"]
			return promptResult(
				"Repository comparison",
				"Compare the security posture of "+repo1+" and "+repo2+". "+
					"For each repository, call nullify_search_findings to get findings across all types. "+
					"Compare the total counts by severity and type. Highlight which repository has more risk and where each needs improvement.",
			), nil
		},
	)

	s.AddPrompt(
		mcplib.Prompt{
			Name:        "fix-critical-findings",
			Description: "Find and fix all critical severity findings.",
		},
		func(ctx context.Context, request mcplib.GetPromptRequest) (*mcplib.GetPromptResult, error) {
			return promptResult(
				"Fix critical findings",
				"Search for all critical severity findings using nullify_search_findings with severity=critical. "+
					"For each finding that supports autofix (sast and sca_dependency types), call nullify_fix_finding to generate a fix and create a PR. "+
					"Report the results: which findings were fixed, which PRs were created, and which findings need manual attention.",
			), nil
		},
	)
}
