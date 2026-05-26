package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Spinner displays a simple progress spinner on stderr.
type Spinner struct {
	msg  string
	done chan struct{}
	once sync.Once
}

// stderrIsTTY reports whether stderr is connected to a terminal. When it is
// not (e.g. CI logs, redirected output), the spinner stays silent to avoid
// polluting logs with ANSI escape sequences and braille frames.
func stderrIsTTY() bool {
	info, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// NewSpinner starts a spinner with the given message. Call Stop() when done.
// If quiet is true, no spinner is displayed but Stop() is still safe to call.
// The spinner is also suppressed when stderr is not a terminal.
func NewSpinner(msg string, quiet bool) *Spinner {
	s := &Spinner{
		msg:  msg,
		done: make(chan struct{}),
	}
	if quiet || !stderrIsTTY() {
		return s
	}

	go func() {
		frames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				fmt.Fprintf(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				fmt.Fprintf(os.Stderr, "\r%c %s", frames[i%len(frames)], s.msg)
				i++
			}
		}
	}()

	return s
}

// Stop stops the spinner.
func (s *Spinner) Stop() {
	s.once.Do(func() {
		close(s.done)
	})
}
