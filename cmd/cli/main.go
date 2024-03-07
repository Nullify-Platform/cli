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

type args struct {
	DAST    *dast.DAST `arg:"subcommand:dast" help:"Test the given app for bugs and vulnerabilities in public networks"`
	Host    string     `arg:"--host" default:"api.nullify.ai" help:"The base URL of your Nullify API instance"`
	Verbose bool       `arg:"-v" help:"Enable verbose logging"`
	Debug   bool       `arg:"-d" help:"Enable debug logging"`

	models.AuthSources
}

func (args) Version() string {
	return logger.Version
}

func main() {
	var args args
	p := arg.MustParse(&args)

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

	nullifyHost, err := lib.SanitizeNullifyHost(args.Host)
	if err != nil {
		logger.Error(
			"invalid host, must be in the format api.<your-instance>.nullify.ai",
			logger.String("host", args.Host),
		)
		os.Exit(1)
	}

	nullifyToken, err := lib.GetNullifyToken(nullifyHost, &args.AuthSources)
	if err != nil {
		logger.Error(
			"failed to get token",
			logger.Err(err),
		)
		os.Exit(1)
	}

	nullifyClient := client.NewNullifyClient(nullifyHost, nullifyToken)

	switch {
	case args.DAST != nil && args.DAST.Path != "":
		err = dast.StartDASTScan(args.DAST, nullifyClient)
		if err != nil {
			logger.Error(
				"failed to start dast scan",
				logger.Err(err),
			)
			os.Exit(1)
		}
	default:
		p.WriteHelp(os.Stdout)
	}
}
