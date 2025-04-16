package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

// ParseAuthConfig reads and parses an authentication configuration file
func ParseAuthConfig(ctx context.Context, configPath string) (*models.AuthConfig, error) {
	if configPath == "" {
		return &models.AuthConfig{}, nil
	}

	logger.L(ctx).Debug("parsing auth config file", logger.String("path", configPath))

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read auth config file: %w", err)
	}

	var authConfig models.AuthConfig
	if err := json.Unmarshal(data, &authConfig); err != nil {
		return nil, fmt.Errorf("failed to parse auth config file: %w", err)
	}

	return &authConfig, nil
}
