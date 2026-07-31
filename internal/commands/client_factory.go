package commands

import (
	"context"

	"github.com/nullify-platform/cli/internal/api"
)

// ClientFactory creates an authenticated API client for a command context.
type ClientFactory func(context.Context) (*api.Client, error)
