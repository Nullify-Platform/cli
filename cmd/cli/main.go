package main

import (
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
}

type LocalScan struct {
	AppName          string   `arg:"--app-name" help:"The unique name of the app to be scanned, you can set this to anything e.g. Core API"`
	Path             string   `arg:"--spec-path" help:"The file path to the OpenAPI file (both yaml and json are supported) e.g. ./openapi.yaml"`
	TargetHost       string   `arg:"--target-host" help:"The base URL of the API to be scanned e.g. https://api.nullify.ai"`
	GitHubOwner      string   `arg:"--github-owner" help:"The GitHub username or organisation to create the Nullify issue dashboard in e.g. nullify-platform"`
	GitHubRepository string   `arg:"--github-repo" help:"The repository name to create the Nullify issue dashboard in e.g. cli"`
	AuthHeaders      []string `arg:"--header" help:"List of headers for the DAST agent to authenticate with your API"`
}

type args struct {
	DAST      *DAST      `arg:"subcommand:dast" help:"Test the given app for bugs and vulnerabilities in public networks"`
	LocalScan *LocalScan `arg:"subcommand:local" help:"Test the given app locally for bugs and vulnerabilities in private networks"`
	Host      string     `arg:"--host" default:"https://api.nullify.ai" help:"The base URL of your Nullify API instance"`
	Verbose   bool       `arg:"-v" help:"Enable verbose logging"`
	Debug     bool       `arg:"-d" help:"Enable debug logging"`

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

	switch {
	case args.DAST != nil && args.DAST.Path != "":
		logger.Info(
			"running fuzz test",
			logger.String("path", args.DAST.Path),
			logger.String("targetHost", args.DAST.TargetHost),
		)
		openAPISpec, err := lib.CreateOpenAPIFile(args.DAST.Path)
		if err != nil {
			os.Exit(1)
		}

		authHeaders, err := lib.ParseAuthHeaders(args.DAST.AuthHeaders)
		if err != nil {
			os.Exit(1)
		}

		httpClient, err := client.NewHTTPClient(args.Host, &args.AuthSources)
		if err != nil {
			logger.Error("failed to create http client", logger.Err(err))
			os.Exit(1)
		}
		out, err := dast.StartScan(httpClient, args.Host, &dast.StartScanInput{
			AppName:     args.DAST.AppName,
			Host:        args.DAST.TargetHost,
			OpenAPISpec: openAPISpec,
			AuthConfig: dast.StartScanAuthConfig{
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

	case args.LocalScan != nil && args.LocalScan.Path != "":
		logger.Info(
			"running local fuzz test",
			logger.String("path", args.LocalScan.Path),
			logger.String("targetHost", args.LocalScan.TargetHost),
		)
		openAPISpec, err := lib.CreateOpenAPIFile(args.LocalScan.Path)
		if err != nil {
			os.Exit(1)
		}

		authHeaders, err := lib.ParseAuthHeaders(args.LocalScan.AuthHeaders)
		if err != nil {
			os.Exit(1)
		}

		httpClient, err := client.NewHTTPClient(args.Host, &args.AuthSources)
		if err != nil {
			logger.Error("failed to create http client", logger.Err(err))
			os.Exit(1)
		}

		out, err := dast.SelfHostedScan(httpClient, args.Host, &dast.SelfHostedInput{
			AppName:     args.LocalScan.AppName,
			Host:        args.LocalScan.TargetHost,
			OpenAPISpec: openAPISpec,
			AuthConfig: dast.StartScanAuthConfig{
				Headers: authHeaders,
			},
			RequestProvider: models.RequestProvider{
				GitHubOwner: args.LocalScan.GitHubOwner,
			},
			RequestDashboardTarget: models.RequestDashboardTarget{
				GitHubRepository: args.LocalScan.GitHubRepository,
			},
		})
		if err != nil {
			logger.Error("failed to send request", logger.Err(err))
			os.Exit(1)
		}
		logger.Info("request sent successfully", logger.String("scanId", out.ScanID))
	default:
		p.WriteHelp(os.Stdout)
	}
}
