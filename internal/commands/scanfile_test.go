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

func TestScanFileCommandNormalizesQuotedUTF16Credential(t *testing.T) {
	root := newTestRoot()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetIn(strings.NewReader(`😀 {"password": "f3Kq9vXz2Lm8Wp4Rb7Nt"}`))
	root.SetArgs([]string{
		"scan-file", "--stdin", "--path", "config.json",
		"--repository", "owner/repo",
	})

	require.NoError(t, root.Execute())

	var findings []scanfile.NormalizedFinding
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &findings))
	require.Equal(t, []scanfile.NormalizedFinding{{
		DetectorClass: "Secret",
		Severity:      "high",
		File:          "config.json",
		StartLine:     1,
		EndLine:       1,
		StartColumn:   18,
		EndColumn:     37,
		CWE:           "CWE-798",
		Message:       "Hardcoded secret detected: Generic API Key",
		Fingerprint:   "932deece382d6b098741c89aeec12a62dded75a2dfb8fe7c77b6b5849f4759dc",
	}}, findings)
}
