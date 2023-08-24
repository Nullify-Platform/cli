package main

import (
	"encoding/json"
	"io"
	"os"
	"strings"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/dast"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"

	"github.com/alexflint/go-arg"
	"gopkg.in/yaml.v3"
)

type DAST struct {
	AppName          string   `arg:"--app-name" help:"The unique name of the app to be scanned, you can set this to anything e.g. Core API"`
	Path             string   `arg:"--spec-path" help:"The file path to the OpenAPI file (both yaml and json are supported) e.g. ./openapi.yaml"`
	TargetHost       string   `arg:"--target-host" help:"The base URL of the API to be scanned e.g. https://api.nullify.ai"`
	GitHubOwner      string   `arg:"--github-owner" help:"The GitHub username or organisation to create the Nullify issue dashboard in e.g. nullify-platform"`
	GitHubRepository string   `arg:"--github-repo" help:"The repository name to create the Nullify issue dashboard in e.g. cli"`
	AuthHeaders      []string `arg:"--header" help:"List of headers for the DAST agent to authenticate with your API"`
}

var args struct {
	DAST *DAST `arg:"subcommand:dast" help:"Test the given app for bugs and vulnerabilities"`

	Host    string `arg:"--host" default:"https://api.nullify.ai" help:"The base URL of your Nullify API instance"`
	Verbose bool   `arg:"-v" help:"Enable verbose logging"`
	Debug   bool   `arg:"-d" help:"Enable debug logging"`

	models.AuthSources
}

func main() {
	arg.MustParse(&args)

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

		data, err := os.Open(args.DAST.Path)
		if err != nil {
			logger.Error(
				"failed to open open api file",
				logger.Err(err),
				logger.String("path", args.DAST.Path),
			)
			os.Exit(1)
		}
		fileData, err := io.ReadAll(data)
		if err != nil {
			logger.Error(
				"failed to read file",
				logger.Err(err),
			)
			os.Exit(1)
		}

		var openAPISpec map[string]interface{}
		if err := json.Unmarshal(fileData, &openAPISpec); err != nil {
			if err := yaml.Unmarshal(fileData, &openAPISpec); err != nil {
				logger.Error("please provide either a json or yaml file")
				os.Exit(1)
			}
		}

		authHeaders := map[string]string{}

		for _, header := range args.DAST.AuthHeaders {
			headerParts := strings.Split(header, ": ")
			if len(headerParts) != 2 {
				logger.Error("please provide headers in the format of 'key: value'")
				os.Exit(1)
			}

			headerName := strings.TrimSpace(headerParts[0])
			headerValue := strings.TrimSpace(headerParts[1])
			authHeaders[headerName] = headerValue
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
	default:
		p := arg.MustParse(&args)
		p.WriteHelp(os.Stdout)
	}
}
