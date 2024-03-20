package dast

import (
	"context"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DAST struct {
	AppName     string   `arg:"--app-name" help:"The unique name of the app to be scanned, you can set this to anything e.g. Core API"`
	Path        string   `arg:"--spec-path" help:"The file path to the OpenAPI file (both yaml and json are supported) e.g. ./openapi.yaml"`
	TargetHost  string   `arg:"--target-host" help:"The base URL of the API to be scanned e.g. https://api.nullify.ai"`
	AuthHeaders []string `arg:"--header" help:"List of headers for the DAST agent to authenticate with your API"`

	GitHubOwner      string `arg:"--github-owner" help:"The GitHub username or organisation"`
	GitHubRepository string `arg:"--github-repo" help:"The repository name to create the Nullify issue dashboard in e.g. cli"`

	// local scan settings
	Local          bool   `arg:"--local" help:"Test the given app locally for bugs and vulnerabilities in private networks"`
	ImageLabel     string `arg:"--image-label" default:"latest" help:"Version of the DAST local image that is used for scanning"`
	ForcePullImage bool   `arg:"--force-pull" help:"Force a docker pull of the latest version of the DAST local image"`
	UseHostNetwork bool   `arg:"--use-host-network" help:"Use the host network for the DAST local scan"`
}

func RunDASTScan(ctx context.Context, dast *DAST, nullifyClient *client.NullifyClient, logLevel string) error {
	spec, err := lib.CreateOpenAPIFile(dast.Path)
	if err != nil {
		logger.Error("failed to create openapi file", logger.Err(err))
		return err
	}

	authHeaders, err := lib.ParseAuthHeaders(dast.AuthHeaders)
	if err != nil {
		logger.Error("failed to parse auth headers", logger.Err(err))
		return err
	}

	if dast.Local {
		logger.Info("starting local scan")
		err = RunLocalScan(
			ctx,
			nullifyClient,
			dast.GitHubOwner,
			&DASTExternalScanInput{
				AppName:     dast.AppName,
				TargetHost:  dast.TargetHost,
				OpenAPISpec: spec,
				AuthConfig: models.AuthConfig{
					Headers: authHeaders,
				},
			},
			dast.ImageLabel,
			dast.ForcePullImage,
			dast.UseHostNetwork,
			logLevel,
		)
		if err != nil {
			logger.Error("failed to send request", logger.Err(err))
			return err
		}
	} else {
		logger.Info("starting server side scan")
		out, err := nullifyClient.DASTStartCloudScan(dast.GitHubOwner, &client.DASTStartCloudScanInput{
			AppName:     dast.AppName,
			Host:        dast.TargetHost,
			TargetHost:  dast.TargetHost,
			OpenAPISpec: spec,
			AuthConfig: models.AuthConfig{
				Headers: authHeaders,
			},
			RequestProvider: models.RequestProvider{
				GitHubOwner: dast.GitHubOwner,
			},
			RequestDashboardTarget: models.RequestDashboardTarget{
				GitHubRepository: dast.GitHubRepository,
			},
		})
		if err != nil {
			logger.Error("failed to send request", logger.Err(err))
			return err
		}

		logger.Info("request sent successfully", logger.String("scanId", out.ScanID))
	}

	return nil
}
