package dast

import (
	"context"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DAST struct {
	AppName     string
	Path        string
	TargetHost  string
	AuthHeaders []string

	GitHubOwner      string
	GitHubRepository string

	// local scan settings
	Local          bool
	ImageLabel     string
	ForcePullImage bool
	UseHostNetwork bool

	AuthConfig string
}

func RunDASTScan(ctx context.Context, dast *DAST, nullifyClient *client.NullifyClient, logLevel string) error {
	spec, err := lib.CreateOpenAPIFile(ctx, dast.Path)
	if err != nil {
		logger.L(ctx).Error("failed to create openapi file", logger.Err(err))
		return err
	}

	authHeaders, err := lib.ParseAuthHeaders(ctx, dast.AuthHeaders)
	if err != nil {
		logger.L(ctx).Error("failed to parse auth headers", logger.Err(err))
		return err
	}

	// Create auth config
	authConfig := models.AuthConfig{
		Headers: authHeaders,
	}

	// Read auth config file
	if dast.AuthConfig != "" {
		fileAuthConfig, err := lib.ParseAuthConfig(ctx, dast.AuthConfig)
		if err != nil {
			logger.L(ctx).Error("failed to parse auth config", logger.Err(err))
			return err
		}
		authConfig = *fileAuthConfig
	}

	if dast.Local {
		logger.L(ctx).Info("starting local scan")
		err = RunLocalScan(
			ctx,
			nullifyClient,
			dast.GitHubOwner,
			dast.GitHubRepository,
			&DASTExternalScanInput{
				AppName:     dast.AppName,
				TargetHost:  dast.TargetHost,
				OpenAPISpec: spec,
				AuthConfig:  authConfig,
			},
			dast.ImageLabel,
			dast.ForcePullImage,
			dast.UseHostNetwork,
			logLevel,
		)
		if err != nil {
			logger.L(ctx).Error("failed to send request", logger.Err(err))
			return err
		}
	} else {
		logger.L(ctx).Info("starting server side scan")
		out, err := nullifyClient.DASTStartCloudScan(ctx, dast.GitHubOwner, &client.DASTStartCloudScanInput{
			AppName:     dast.AppName,
			Host:        dast.TargetHost,
			TargetHost:  dast.TargetHost,
			OpenAPISpec: spec,
			AuthConfig:  authConfig,
			RequestProvider: models.RequestProvider{
				GitHubOwner: dast.GitHubOwner,
			},
			RequestDashboardTarget: models.RequestDashboardTarget{
				GitHubRepository: dast.GitHubRepository,
			},
		})
		if err != nil {
			logger.L(ctx).Error("failed to send request", logger.Err(err))
			return err
		}

		logger.L(ctx).Info("request sent successfully", logger.String("scanId", out.ScanID))
	}

	return nil
}
