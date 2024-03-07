package dast

import (
	"os"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"
)

type DAST struct {
	AppName          string   `arg:"--app-name" help:"The unique name of the app to be scanned, you can set this to anything e.g. Core API"`
	Path             string   `arg:"--spec-path" help:"The file path to the OpenAPI file (both yaml and json are supported) e.g. ./openapi.yaml"`
	TargetHost       string   `arg:"--target-host" help:"The base URL of the API to be scanned e.g. https://api.nullify.ai"`
	GitHubOwner      string   `arg:"--github-owner" help:"The GitHub username or organisation to create the Nullify issue dashboard in e.g. nullify-platform"`
	GitHubRepository string   `arg:"--github-repo" help:"The repository name to create the Nullify issue dashboard in e.g. cli"`
	AuthHeaders      []string `arg:"--header" help:"List of headers for the DAST agent to authenticate with your API"`
	Local            bool     `arg:"--local" help:"Test the given app locally for bugs and vulnerabilities in private networks"`
	Version          string   `arg:"--version" default:"latest" help:"Version of the DAST local image that is used for scanning"`
}

func StartDASTScan(dast *DAST, nullifyClient *client.NullifyClient) error {
	openAPISpec, err := lib.CreateOpenAPIFile(dast.Path)
	if err != nil {
		logger.Error("failed to create openapi file", logger.Err(err))
		os.Exit(1)
	}

	authHeaders, err := lib.ParseAuthHeaders(dast.AuthHeaders)
	if err != nil {
		logger.Error("failed to parse auth headers", logger.Err(err))
		os.Exit(1)
	}

	if dast.Local {
		logger.Info("starting local scan")
		err = StartLocalScan(nullifyClient, &StartLocalScanInput{
			AppName:     dast.AppName,
			TargetHost:  dast.TargetHost,
			Version:     dast.Version,
			OpenAPISpec: openAPISpec,
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
			os.Exit(1)
		}
	} else {
		logger.Info("starting server side scan")
		out, err := nullifyClient.DASTStartCloudScan(&client.DASTStartCloudScanInput{
			AppName:     dast.AppName,
			Host:        dast.TargetHost,
			TargetHost:  dast.TargetHost,
			OpenAPISpec: openAPISpec,
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
			os.Exit(1)
		}

		logger.Info("request sent successfully", logger.String("scanId", out.ScanID))
	}

	return nil
}
