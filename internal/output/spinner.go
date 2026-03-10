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

// NewSpinner starts a spinner with the given message. Call Stop() when done.
// If quiet is true, no spinner is displayed but Stop() is still safe to call.
func NewSpinner(msg string, quiet bool) *Spinner {
	s := &Spinner{
		msg:  msg,
		done: make(chan struct{}),
	}
	if quiet {
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
