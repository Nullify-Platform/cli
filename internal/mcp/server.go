package mcp

import (
	"context"
	"fmt"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/logger/pkg/logger"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func Serve(ctx context.Context, host string, token string, queryParams map[string]string, toolSet ToolSet) error {
	return ServeWithClient(ctx, client.NewNullifyClient(host, token), queryParams, toolSet)
}

func ServeWithClient(ctx context.Context, nullifyClient *client.NullifyClient, queryParams map[string]string, toolSet ToolSet) error {
	s := server.NewMCPServer(
		"Nullify",
		logger.Version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
		server.WithPromptCapabilities(true),
	)

	registerTools(s, nullifyClient, queryParams, toolSet)
	registerResources(s, nullifyClient, queryParams)
	registerPrompts(s)

	logger.L(ctx).Debug("starting MCP server over stdio", logger.String("toolSet", string(toolSet)))

	stdioServer := server.NewStdioServer(s)
	return stdioServer.Listen(ctx, nil, nil)
}

func registerTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string, toolSet ToolSet) {
	switch toolSet {
	case ToolSetMinimal:
		// Composites only (5 tools)
		registerCompositeTools(s, c, queryParams)

	case ToolSetFindings:
		// Unified + composites + comments
		registerUnifiedTools(s, c, queryParams)
		registerCompositeTools(s, c, queryParams)
		registerCommentTools(s, c, queryParams)

	case ToolSetAdmin:
		// Admin + classifier + manager + infrastructure + composites
		registerAdminTools(s, c, queryParams)
		registerClassifierTools(s, c, queryParams)
		registerManagerTools(s, c, queryParams)
		registerInfrastructureTools(s, c, queryParams)
		registerCompositeTools(s, c, queryParams)

	case ToolSetAll:
		// Everything including all scanner-specific + unified
		registerSASTTools(s, c, queryParams)
		registerSCATools(s, c, queryParams)
		registerSecretsTools(s, c, queryParams)
		registerPentestTools(s, c, queryParams)
		registerBughuntTools(s, c, queryParams)
		registerCSPMTools(s, c, queryParams)
		registerAdminTools(s, c, queryParams)
		registerClassifierTools(s, c, queryParams)
		registerManagerTools(s, c, queryParams)
		registerInfrastructureTools(s, c, queryParams)
		registerCodeReviewTools(s, c, queryParams)
		registerCommentTools(s, c, queryParams)
		registerCompositeTools(s, c, queryParams)
		registerUnifiedTools(s, c, queryParams)

	default: // ToolSetDefault
		// Unified + composites + classifier + infrastructure + manager + code reviews + comments
		registerUnifiedTools(s, c, queryParams)
		registerCompositeTools(s, c, queryParams)
		registerClassifierTools(s, c, queryParams)
		registerInfrastructureTools(s, c, queryParams)
		registerManagerTools(s, c, queryParams)
		registerCodeReviewTools(s, c, queryParams)
		registerCommentTools(s, c, queryParams)
		registerAdminTools(s, c, queryParams)
	}
}

func buildQueryString(queryParams map[string]string, extra ...string) string {
	return lib.BuildQueryString(queryParams, extra...)
}

func getStringArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

func getIntArg(args map[string]any, key string, defaultVal int) int {
	v, ok := args[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	default:
		return defaultVal
	}
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent(fmt.Sprintf("Error: %v", err)),
		},
		IsError: true,
	}
}

func toolResult(data string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.NewTextContent(data),
		},
	}
}
