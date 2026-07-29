package mcp

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/nullify-platform/cli/internal/api"
	"github.com/nullify-platform/cli/internal/logger"
	"github.com/stretchr/testify/require"
)

func TestGetStringArg(t *testing.T) {
	args := map[string]any{
		"name":  "test",
		"count": float64(42),
	}

	if got := getStringArg(args, "name"); got != "test" {
		t.Errorf("getStringArg(name) = %q, want %q", got, "test")
	}
	if got := getStringArg(args, "missing"); got != "" {
		t.Errorf("getStringArg(missing) = %q, want empty", got)
	}
	if got := getStringArg(args, "count"); got != "" {
		t.Errorf("getStringArg(count) = %q, want empty (wrong type)", got)
	}
}

func TestGetIntArg(t *testing.T) {
	args := map[string]any{
		"limit": float64(50),
		"page":  float64(3),
		"name":  "test",
	}

	if got := getIntArg(args, "limit", 20); got != 50 {
		t.Errorf("getIntArg(limit) = %d, want 50", got)
	}
	if got := getIntArg(args, "missing", 20); got != 20 {
		t.Errorf("getIntArg(missing) = %d, want 20 (default)", got)
	}
	if got := getIntArg(args, "name", 10); got != 10 {
		t.Errorf("getIntArg(name) = %d, want 10 (default for wrong type)", got)
	}
}

func TestServeWithClientIOHandlesEOF(t *testing.T) {
	ctx, err := logger.ConfigureDevelopmentLogger(context.Background(), "error")
	require.NoError(t, err)

	err = serveWithClientIO(
		ctx,
		api.NewClient("acme.nullify.ai", "token", map[string]string{}),
		ToolSetDefault,
		strings.NewReader(""),
		io.Discard,
	)

	require.NoError(t, err)
}
