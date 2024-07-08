package config

import (
	"context"

	"github.com/nullify-platform/logger/pkg/logger"
)

func GetTestLogger() (context.Context, error) {
	ctx := context.Background()
	return logger.ConfigureDevelopmentLogger(ctx, "debug")
}
