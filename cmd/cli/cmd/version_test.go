package cmd

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// A build without ldflags, such as `go install`, still answers --version.
func TestRootVersionFlag(t *testing.T) {
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"--version"})

	require.NoError(t, rootCmd.Execute())
	require.Contains(t, out.String(), "nullify version ")
	require.NotContains(t, out.String(), "unknown flag")
}
