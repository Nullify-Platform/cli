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

type exitCoder interface {
	ExitCode() int
}

func withExitCode(code int, err error) error {
	if err == nil {
		return nil
	}
	return &exitCodeError{code: code, err: err}
}

func authError(format string, args ...any) error {
	return withExitCode(ExitAuthError, fmt.Errorf(format, args...))
}

func networkError(format string, args ...any) error {
	return withExitCode(ExitNetworkError, fmt.Errorf(format, args...))
}

// ExitCodeForError resolves the process exit code for a top-level error.
// Plain errors map to exit code 1; coded errors use their embedded code.
func ExitCodeForError(err error) int {
	if err == nil {
		return ExitSuccess
	}
	var coded exitCoder
	if errors.As(err, &coded) {
		return coded.ExitCode()
	}
	return 1
}
