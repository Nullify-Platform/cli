package commands

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/nullify-platform/cli/internal/scanfile"
)

func newTestRoot() *cobra.Command {
	root := &cobra.Command{Use: "root"}
	RegisterScanFileCommand(root)
	return root
}

// fakeAWSKey builds an AWS-access-key-ID-shaped fixture via concatenation so
// the 20-character string never appears contiguous in this file's own
// source text and can't trip a secret scanner on this repo's own commits.
func fakeAWSKey() string {
	return "AKIA" + "ABCDEFGHIJKLMNOP"
}

func TestRegisterScanFileCommandAddsScanFile(t *testing.T) {
	root := newTestRoot()
	cmd, _, err := root.Find([]string{"scan-file"})
	require.NoError(t, err)
	require.Equal(t, "scan-file", cmd.Name())
}

func TestScanFileCommandScansDiskFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.go")
	content := "awsKey := \"" + fakeAWSKey() + "\"\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	root := newTestRoot()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"scan-file", path})

	require.NoError(t, root.Execute())

	var findings []scanfile.NormalizedFinding
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &findings))
	require.NotEmpty(t, findings)
	require.Equal(t, path, findings[0].File)
}

func TestScanFileCommandScansStdin(t *testing.T) {
	content := "awsKey := \"" + fakeAWSKey() + "\"\n"

	root := newTestRoot()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetIn(strings.NewReader(content))
	root.SetArgs([]string{"scan-file", "--stdin", "--path", "config.go", "--repository", "owner/repo"})

	require.NoError(t, root.Execute())

	var findings []scanfile.NormalizedFinding
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &findings))
	require.NotEmpty(t, findings)
	require.Equal(t, "config.go", findings[0].File)
}

func TestScanFileCommandRequiresPathWithStdin(t *testing.T) {
	root := newTestRoot()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader("content"))
	root.SetArgs([]string{"scan-file", "--stdin"})

	require.Error(t, root.Execute())
}

func TestScanFileCommandRejectsPathAndStdinTogether(t *testing.T) {
	root := newTestRoot()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader("content"))
	root.SetArgs([]string{"scan-file", "--stdin", "--path", "a.go", "b.go"})

	require.Error(t, root.Execute())
}

func TestScanFileCommandCleanFileProducesEmptyArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	require.NoError(t, os.WriteFile(path, []byte("package main\n\nfunc main() {}\n"), 0o600))

	root := newTestRoot()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"scan-file", path})

	require.NoError(t, root.Execute())
	require.Equal(t, "[]\n", stdout.String())
}
