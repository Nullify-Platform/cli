package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExitCodeForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, ExitSuccess},
		{"plain error", errors.New("boom"), 1},
		{"auth error", authError("nope"), ExitAuthError},
		{"network error", networkError("nope"), ExitNetworkError},
		{"findings error", findingsError("nope"), ExitFindings},
		{"explicit code 1", withExitCode(1, errors.New("x")), 1},
		{"wrapped coded error", fmt.Errorf("ctx: %w", authError("nope")), ExitAuthError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, ExitCodeForError(tt.err))
		})
	}
}

func TestWithExitCodePreservesMessage(t *testing.T) {
	err := withExitCode(ExitNetworkError, errors.New("fetching metrics: timeout"))
	require.Equal(t, "fetching metrics: timeout", err.Error())

	var coded *exitCodeError
	require.True(t, errors.As(err, &coded))
	require.Equal(t, ExitNetworkError, coded.ExitCode())
}
