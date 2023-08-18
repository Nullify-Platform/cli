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
	AppName          string   `arg:"--app-name" help:"name of the app to be scanned"`
	Path             string   `arg:"--spec-path" help:"file path to the open api file"`
	TargetHost       string   `arg:"--target-host"`
	GitHubOwner      string   `arg:"--github-owner" help:"github owner to create the issue in e.g. nullify-platform"`
	GitHubRepository string   `arg:"--github-repo" help:"repository name to create the issue in e.g. cli"`
	AuthHeaders      []string `arg:"--header" help:"headers for the DAST agent to authenticate with your API"`
}

var args struct {
	DAST    *DAST  `arg:"subcommand:test" help:"test the given API for bugs and vulnerabilities"`
	Host    string `arg:"-h,--host" default:"https://api.nullify.ai"`
	Verbose bool   `arg:"-v" help:"enable verbose logging"`
	Debug   bool   `arg:"-d" help:"enable debug logging"`
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

		httpClient := client.NewHTTPClient()

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
