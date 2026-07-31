package output

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/nullify-platform/cli/internal/terminal"
)

// Spinner displays a simple progress spinner on stderr.
type Spinner struct {
	msg  string
	done chan struct{}
	stop chan struct{}
	once sync.Once
}

func stderrIsTTY() bool {
	return terminal.IsInteractive(os.Stderr)
}

// NewSpinner starts a spinner with the given message. Call Stop() when done.
// If quiet is true, no spinner is displayed but Stop() is still safe to call.
// The spinner is also suppressed when stderr is not a terminal.
func NewSpinner(msg string, quiet bool) *Spinner {
	return newSpinner(msg, quiet, stderrIsTTY(), os.Stderr)
}

func newSpinner(
	msg string,
	quiet bool,
	interactive bool,
	writer io.Writer,
) *Spinner {
	s := &Spinner{
		msg:  msg,
		done: make(chan struct{}),
		stop: make(chan struct{}),
	}
	if quiet || !interactive {
		close(s.stop)
		return s
	}

	go func() {
		defer close(s.stop)
		frames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
		i := 0
		ticker := time.NewTicker(80 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.done:
				fmt.Fprint(writer, "\r\033[K")
				return
			case <-ticker.C:
				fmt.Fprintf(writer, "\r%c %s", frames[i%len(frames)], s.msg)
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
	<-s.stop
}
