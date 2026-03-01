package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/nullify-platform/cli/internal/client"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func doGet(ctx context.Context, c *client.NullifyClient, path string) (*mcp.CallToolResult, error) {
	return doRequest(ctx, c, "GET", path, nil)
}

func doPost(ctx context.Context, c *client.NullifyClient, path string, payload any) (*mcp.CallToolResult, error) {
	return doRequest(ctx, c, "POST", path, payload)
}

func doPut(ctx context.Context, c *client.NullifyClient, path string, payload any) (*mcp.CallToolResult, error) {
	return doRequest(ctx, c, "PUT", path, payload)
}

func doRequest(ctx context.Context, c *client.NullifyClient, method string, path string, payload any) (*mcp.CallToolResult, error) {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return toolError(err), nil
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, bodyReader)
	if err != nil {
		return toolError(err), nil
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return toolError(err), nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return toolError(err), nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return toolError(fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))), nil
	}

	return toolResult(string(body)), nil
}

// makeGetHandler creates a handler for list endpoints with standard filtering
func makeGetHandler(c *client.NullifyClient, basePath string, queryParams map[string]string) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.GetArguments()
		extra := []string{}
		for key := range args {
			if key == "limit" {
				extra = append(extra, key, fmt.Sprintf("%d", getIntArg(args, key, 20)))
			} else if s := getStringArg(args, key); s != "" {
				extra = append(extra, key, s)
			}
		}
		qs := buildQueryString(queryParams, extra...)
		return doGet(ctx, c, basePath+qs)
	}
}

// makeGetByIDHandler creates a handler that gets a single resource by ID
func makeGetByIDHandler(c *client.NullifyClient, basePath string, queryParams map[string]string) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.GetArguments()
		id := getStringArg(args, "id")
		qs := buildQueryString(queryParams)
		return doGet(ctx, c, fmt.Sprintf("%s/%s%s", basePath, id, qs))
	}
}
