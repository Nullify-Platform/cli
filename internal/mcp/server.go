package mcp

import (
	"context"
	"fmt"
	"net/url"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/logger/pkg/logger"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func Serve(ctx context.Context, host string, token string, queryParams map[string]string) error {
	nullifyClient := client.NewNullifyClient(host, token)

	s := server.NewMCPServer(
		"Nullify",
		logger.Version,
		server.WithToolCapabilities(true),
	)

	registerTools(s, nullifyClient, queryParams)

	logger.L(ctx).Debug("starting MCP server over stdio")

	stdioServer := server.NewStdioServer(s)
	return stdioServer.Listen(ctx, nil, nil)
}

func registerTools(s *server.MCPServer, c *client.NullifyClient, queryParams map[string]string) {
	registerSASTTools(s, c, queryParams)
	registerSCATools(s, c, queryParams)
	registerSecretsTools(s, c, queryParams)
	registerDASTTools(s, c, queryParams)
	registerCSPMTools(s, c, queryParams)
	registerAdminTools(s, c, queryParams)
	registerClassifierTools(s, c, queryParams)
	registerManagerTools(s, c, queryParams)
	registerCompositeTools(s, c, queryParams)
}

func buildQueryString(queryParams map[string]string, extra ...string) string {
	params := url.Values{}
	for k, v := range queryParams {
		params.Set(k, v)
	}
	for i := 0; i+1 < len(extra); i += 2 {
		if extra[i+1] != "" {
			params.Set(extra[i], extra[i+1])
		}
	}

	if len(params) == 0 {
		return ""
	}

	return "?" + params.Encode()
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
