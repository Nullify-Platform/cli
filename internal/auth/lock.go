package auth

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// storeLockWait bounds how long a write waits for another process's.
var storeLockWait = 30 * time.Second

// withStoreLock runs fn holding the lock on ~/.nullify, so two processes
// (a terminal command and a running MCP server, say) rewriting credentials
// or hosts at once cannot drop each other's update. fn must not take it again.
func withStoreLock(fn func() error) error {
	if err := ensureConfigDir(); err != nil {
		return err
	}
	dir, err := configDir()
	if err != nil {
		return err
	}

	lock := flock.New(filepath.Join(dir, ".lock"))
	ctx, cancel := context.WithTimeout(context.Background(), storeLockWait)
	defer cancel()
	locked, err := lock.TryLockContext(ctx, 20*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock %s: %w", dir, err)
	}
	if !locked {
		return fmt.Errorf("lock %s: timed out", dir)
	}
	defer func() { _ = lock.Unlock() }()

	return fn()
}
