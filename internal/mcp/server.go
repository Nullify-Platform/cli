package mcp

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/logger"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ServeWithClient runs the MCP server over stdio, driving the generated
// api.Client. Tenant/owner scoping travels in the client's default query params.
func ServeWithClient(ctx context.Context, apiClient *api.Client, toolSet ToolSet) error {
	return serveWithClientIO(ctx, apiClient, toolSet, os.Stdin, os.Stdout)
}

func serveWithClientIO(ctx context.Context, apiClient *api.Client, toolSet ToolSet, stdin io.Reader, stdout io.Writer) error {
	s := server.NewMCPServer(
		"Nullify",
		logger.Version,
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, false),
		server.WithPromptCapabilities(true),
	)

	registerTools(s, apiClient, toolSet)
	registerResources(s, apiClient)
	registerPrompts(s)

	logger.L(ctx).Debug("starting MCP server over stdio", logger.String("toolSet", string(toolSet)))

	stdioServer := server.NewStdioServer(s)
	return stdioServer.Listen(ctx, stdin, stdout)
}

// registerTools selects which tools to expose. The default set is deliberately
// lean (the core find→investigate→scan→threat→remediate workflow) to keep the
// toolset small enough for reliable LLM selection; broader sets are opt-in.
func registerTools(s *server.MCPServer, c *api.Client, toolSet ToolSet) {
	switch toolSet {
	case ToolSetMinimal:
		registerCompositeTools(s, c)

	case ToolSetFindings:
		registerUnifiedTools(s, c)
		registerCompositeTools(s, c)

	case ToolSetAdmin:
		registerAdminTools(s, c)
		registerContextTools(s, c)
		registerManagerTools(s, c)
		registerCompositeTools(s, c)

	case ToolSetAll:
		registerUnifiedTools(s, c)
		registerCompositeTools(s, c)
		registerContextTools(s, c)
		registerManagerTools(s, c)
		registerAdminTools(s, c)
		registerScanTools(s, c)
		registerThreatTools(s, c)
		registerCSPMTools(s, c)
		registerPentestTools(s, c)

	default: // ToolSetDefault — lean
		registerUnifiedTools(s, c)
		registerCompositeTools(s, c)
		registerContextTools(s, c)
		registerScanTools(s, c)
		registerThreatTools(s, c)
	}
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

func getFloatArg(args map[string]any, key string) float64 {
	switch n := args[key].(type) {
	case float64:
		return n
	case int:
		return float64(n)
	default:
		return 0
	}
}

func toolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(fmt.Sprintf("Error: %v", err))},
		IsError: true,
	}
}

func toolResult(data string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{mcp.NewTextContent(data)},
	}
}
