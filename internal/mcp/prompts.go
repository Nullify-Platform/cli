package mcp

import (
	"context"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

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

			return &mcplib.GetPromptResult{
				Description: "Security review prompt",
				Messages: []mcplib.PromptMessage{
					{
						Role:    mcplib.RoleUser,
						Content: mcplib.NewTextContent(prompt),
					},
				},
			}, nil
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

			return &mcplib.GetPromptResult{
				Description: "Finding triage prompt",
				Messages: []mcplib.PromptMessage{
					{
						Role:    mcplib.RoleUser,
						Content: mcplib.NewTextContent(prompt),
					},
				},
			}, nil
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

			return &mcplib.GetPromptResult{
				Description: "Vulnerability explanation prompt",
				Messages: []mcplib.PromptMessage{
					{
						Role:    mcplib.RoleUser,
						Content: mcplib.NewTextContent(prompt),
					},
				},
			}, nil
		},
	)
}
