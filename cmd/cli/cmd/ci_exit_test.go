package cmd

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestCICommandsReportBadInputAsAUsageError(t *testing.T) {
	tests := []struct {
		name    string
		command *cobra.Command
		flags   map[string]string
	}{
		{"an unknown gate threshold", ciGateCmd, map[string]string{"severity-threshold": "severe"}},
		{"an empty gate threshold", ciGateCmd, map[string]string{"severity-threshold": ""}},
		{"an unknown report format", ciReportCmd, map[string]string{"format": "html"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			api := serveScannerAPI(t, emptyFindings)

			_, err := runCI(t, tt.command, tt.flags)

			require.Equal(t, ExitUsageError, ExitCodeForError(err))
			require.Empty(t, api.requests(), "bad input is rejected before any request")
		})
	}
}

func TestCICommandsReportFlagParseErrorsAsAUsageError(t *testing.T) {
	for _, command := range []*cobra.Command{ciGateCmd, ciReportCmd} {
		t.Run(command.Name(), func(t *testing.T) {
			err := command.FlagErrorFunc()(command, errors.New("unknown flag: --bogus"))

			require.Equal(t, ExitUsageError, ExitCodeForError(err))
			require.ErrorContains(t, err, "unknown flag: --bogus")
		})
	}
}

func TestCIGateExitsWithTheAuthCodeWhenAccessIsRefused(t *testing.T) {
	tests := []struct {
		name   string
		status int
		exit   int
	}{
		{"401", http.StatusUnauthorized, ExitAuthError},
		{"403", http.StatusForbidden, ExitAuthError},
		{"400", http.StatusBadRequest, ExitNetworkError},
		{"404", http.StatusNotFound, ExitNetworkError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useCIEnv(t)
			serveScannerAPI(t, func(*http.Request) (int, string) {
				return tt.status, `{"error":"refused"}`
			})

			_, err := runCI(t, ciGateCmd, map[string]string{"type": "secrets", "repo": "acme/app"})

			require.Equal(t, tt.exit, ExitCodeForError(err))
		})
	}
}

func TestCIReportExitsWithTheAuthCodeWhenEveryScannerRefusesAccess(t *testing.T) {
	useCIEnv(t)
	serveScannerAPI(t, func(*http.Request) (int, string) {
		return http.StatusForbidden, `{"error":"missing permission"}`
	})

	_, err := runCI(t, ciReportCmd, map[string]string{"repo": "acme/app"})

	require.Equal(t, ExitAuthError, ExitCodeForError(err))
}

func TestReadFindingsBodyRejectsAResponseOverTheBound(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr error
	}{
		{"under the bound", `{"a":1}`, nil},
		{"at the bound", `0123456789`, nil},
		{"over the bound", `0123456789!`, errUnreadableFindings},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := readFindingsBody(strings.NewReader(tt.body), 10)

			require.ErrorIs(t, err, tt.wantErr)
			if tt.wantErr == nil {
				require.Equal(t, tt.body, body)
			}
		})
	}
}
