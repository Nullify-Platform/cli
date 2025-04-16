package main

import (
	"context"
	"os"

	"github.com/nullify-platform/cli/internal/client"
	"github.com/nullify-platform/cli/internal/dast"
	"github.com/nullify-platform/cli/internal/lib"
	"github.com/nullify-platform/cli/internal/models"
	"github.com/nullify-platform/logger/pkg/logger"

	"github.com/alexflint/go-arg"
)

type args struct {
	DAST       *dast.DAST `arg:"subcommand:dast" help:"Test the given app for bugs and vulnerabilities"`
	Host       string     `arg:"--host" default:"api.nullify.ai" help:"The base URL of your Nullify API instance"`
	Verbose    bool       `arg:"-v" help:"Enable verbose logging"`
	Debug      bool       `arg:"-d" help:"Enable debug logging"`
	AuthConfig string     `arg:"--auth-config" help:"The path to the auth config file"`
	models.AuthSources
}

func (args) Version() string {
	return logger.Version
}

func main() {
	ctx := context.TODO()

	var args args
	p := arg.MustParse(&args)

	logLevel := "warn"
	if args.Verbose {
		logLevel = "info"
	}
	if args.Debug {
		logLevel = "debug"
	}
	ctx, err := logger.ConfigureDevelopmentLogger(ctx, logLevel)
	if err != nil {
		panic(err)
	}
	defer logger.L(ctx).Sync()

	switch {
	case args.DAST != nil && args.DAST.Path != "":
		nullifyClient := getNullifyClient(ctx, &args)
		err = dast.RunDASTScan(ctx, args.DAST, nullifyClient, logLevel)
		if err != nil {
			logger.L(ctx).Error(
				"failed to run dast scan",
				logger.Err(err),
			)
			os.Exit(1)
		}
	default:
		p.WriteHelp(os.Stdout)
	}
}

func getNullifyClient(ctx context.Context, args *args) *client.NullifyClient {
	nullifyHost, err := lib.SanitizeNullifyHost(args.Host)
	if err != nil {
		logger.L(ctx).Error(
			"invalid host, must be in the format api.<your-instance>.nullify.ai",
			logger.String("host", args.Host),
		)
		os.Exit(1)
	}

	nullifyToken, err := lib.GetNullifyToken(ctx, nullifyHost, &args.AuthSources)
	if err != nil {
		logger.L(ctx).Error(
			"failed to get token",
			logger.Err(err),
		)
		os.Exit(1)
	}

	return client.NewNullifyClient(nullifyHost, nullifyToken)
}
