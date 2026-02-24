package main

import (
	"os"

	"github.com/nullify-platform/cli/cmd/cli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
