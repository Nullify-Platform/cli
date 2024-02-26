package main

import (
	"net/url"
	"os"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/dast"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"

	"github.com/alexflint/go-arg"
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

type args struct {
	DAST    *DAST  `arg:"subcommand:dast" help:"Test the given app for bugs and vulnerabilities in public networks"`
	Host    string `arg:"--host" default:"api.nullify.ai" help:"The base URL of your Nullify API instance"`
	Verbose bool   `arg:"-v" help:"Enable verbose logging"`
	Debug   bool   `arg:"-d" help:"Enable debug logging"`

	models.AuthSources
}

func (args) Version() string {
	return logger.Version
}

func main() {
	var args args
	p := arg.MustParse(&args)

	// Configure logger
	logLevel := "warn"
	if args.Verbose {
		logLevel = "info"
	}
	if args.Debug {
		logLevel = "debug"
	}
	log, err := logger.ConfigureDevelopmentLogger(logLevel)
	if err != nil {
		panic(err)
	}
	defer log.Sync()

	nullifyURL, err := url.Parse(args.Host)
	if err != nil {
		logger.Error(
			"failed to parse host",
			logger.Err(err),
			logger.String("host", args.Host),
		)
		os.Exit(1)
	}

	switch {
	case args.DAST != nil && args.DAST.Path != "":
		logger.Info(
			"running dast scan",
			logger.String("path", args.DAST.Path),
			logger.String("targetHost", args.DAST.TargetHost),
		)

		openAPISpec, err := lib.CreateOpenAPIFile(args.DAST.Path)
		if err != nil {
			logger.Error("failed to create openapi file", logger.Err(err))
			os.Exit(1)
		}

		authHeaders, err := lib.ParseAuthHeaders(args.DAST.AuthHeaders)
		if err != nil {
			logger.Error("failed to parse auth headers", logger.Err(err))
			os.Exit(1)
		}

		httpClient, err := client.NewHTTPClient(nullifyURL.Host, &args.AuthSources)
		if err != nil {
			logger.Error("failed to create http client", logger.Err(err))
			os.Exit(1)
		}

		if args.DAST.Local {
			err = dast.DASTLocalScan(httpClient, &dast.DASTLocalScanInput{
				AppName:     args.DAST.AppName,
				Host:        nullifyURL.Host,
				TargetHost:  args.DAST.TargetHost,
				Version:     args.DAST.Version,
				OpenAPISpec: openAPISpec,
				AuthSources: args.AuthSources,
				AuthConfig: models.AuthConfig{
					Headers: authHeaders,
				},
				RequestProvider: models.RequestProvider{
					GitHubOwner: args.DAST.GitHubOwner,
				},
				RequestDashboardTarget: models.RequestDashboardTarget{
					GitHubRepository: args.DAST.GitHubRepository,
				},
			})
			if err != nil {
				logger.Error("failed to send request", logger.Err(err))
				os.Exit(1)
			}
		} else {
			out, err := dast.StartScan(httpClient, nullifyURL.Host, &dast.StartScanInput{
				AppName:     args.DAST.AppName,
				Host:        args.DAST.TargetHost,
				OpenAPISpec: openAPISpec,
				AuthConfig: models.AuthConfig{
					Headers: authHeaders,
				},
				RequestProvider: models.RequestProvider{
					GitHubOwner: args.DAST.GitHubOwner,
				},
				RequestDashboardTarget: models.RequestDashboardTarget{
					GitHubRepository: args.DAST.GitHubRepository,
				},
			})
			if err != nil {
				logger.Error("failed to send request", logger.Err(err))
				os.Exit(1)
			}

			logger.Info("request sent successfully", logger.String("scanId", out.ScanID))
		}
	default:
		p.WriteHelp(os.Stdout)
	}
}
