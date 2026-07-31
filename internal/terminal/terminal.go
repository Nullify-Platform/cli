package terminal

import (
	"os"

	"golang.org/x/term"
)

// IsInteractive reports whether a file is attached to a terminal.
func IsInteractive(file *os.File) bool {
	return term.IsTerminal(int(file.Fd()))
}
