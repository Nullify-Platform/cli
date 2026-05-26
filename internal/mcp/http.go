package mcp

import (
	"github.com/mark3labs/mcp-go/mcp"
)

// wrap converts a generated api.Client call result ([]byte, error) into an MCP
// tool result. Every tool routes through the typed client, so this is the one
// place that turns a client response into a tool payload.
func wrap(data []byte, err error) (*mcp.CallToolResult, error) {
	if err != nil {
		return toolError(err), nil
	}
	return toolResult(string(data)), nil
}
