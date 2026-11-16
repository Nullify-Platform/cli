package lib

import "errors"

// ErrGitRefOption means a revision starts with an option prefix.
var ErrGitRefOption = errors.New("git ref must not start with '-'")
