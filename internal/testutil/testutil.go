package testutil

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/logger/pkg/logger"
)

// MockNullifyClient creates a NullifyClient that talks to a test HTTP server.
// The provided handler processes all requests.
func MockNullifyClient(handler http.Handler) (*client.NullifyClient, *httptest.Server) {
	server := httptest.NewServer(handler)

	c := &client.NullifyClient{
		Host:       server.Listener.Addr().String(),
		BaseURL:    server.URL,
		Token:      "test-token",
		HttpClient: server.Client(),
	}

	return c, server
}

// TestContext returns a context with a debug logger configured.
func TestContext() context.Context {
	ctx := context.Background()
	ctx, _ = logger.ConfigureDevelopmentLogger(ctx, "debug")
	return ctx
}

// GetTestLogger returns a context with a debug logger configured.
// This is a compatibility wrapper around TestContext for tests that expect an error return.
func GetTestLogger() (context.Context, error) {
	ctx := context.Background()
	return logger.ConfigureDevelopmentLogger(ctx, "debug")
}
