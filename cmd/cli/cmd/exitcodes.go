package cmd

import (
	"errors"
	"fmt"
)

// Exit codes for the CLI.
const (
	ExitSuccess      = 0
	ExitFindings     = 1
	ExitAuthError    = 2
	ExitNetworkError = 3
)

// exitCodeError wraps an error with a specific process exit code. RunE handlers
// return these so that exit-code mapping happens in exactly one place
// (main.go), instead of scattered os.Exit calls that would skip deferred
// cleanup such as logger.Close.
type exitCodeError struct {
	code int
	err  error
}

func (e *exitCodeError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *exitCodeError) Unwrap() error {
	return e.err
}

// ExitCode returns the process exit code associated with the error.
func (e *exitCodeError) ExitCode() int {
	return e.code
}

// withExitCode wraps err so that the CLI exits with the given code. The
// underlying error is preserved (and printed once by cobra).
func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitCodeError{code: code, err: err}
}

// authError builds an exit-code error for authentication failures.
func authError(format string, args ...any) error {
	return withExitCode(ExitAuthError, fmt.Errorf(format, args...))
}

// networkError builds an exit-code error for network/API failures.
func networkError(format string, args ...any) error {
	return withExitCode(ExitNetworkError, fmt.Errorf(format, args...))
}

// findingsError builds an exit-code error indicating findings exceeded the gate.
func findingsError(format string, args ...any) error {
	return withExitCode(ExitFindings, fmt.Errorf(format, args...))
}

// ExitCodeForError resolves the process exit code for a top-level error.
// Plain errors map to exit code 1; coded errors use their embedded code.
func ExitCodeForError(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var coded *exitCodeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return 1
}
