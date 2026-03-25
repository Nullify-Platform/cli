package logger

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func TestConfigureDevelopmentLogger_RoundTrip(t *testing.T) {
	ctx, err := ConfigureDevelopmentLogger(context.Background(), "debug")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	l := L(ctx)
	if l == nil || l.Logger == nil {
		t.Fatal("expected non-nil logger from context")
	}

	// Should not panic
	l.Debug("test debug message", String("key", "value"))
	l.Info("test info message", Int("count", 42))
	l.Warn("test warn message", Err(nil))
	l.Error("test error message", Any("data", map[string]int{"a": 1}))
}

func TestL_MissingContext_ReturnsNop(t *testing.T) {
	l := L(context.Background())
	if l == nil || l.Logger == nil {
		t.Fatal("expected non-nil no-op logger")
	}

	// Should not panic on no-op logger
	l.Info("this should be silently discarded")
	l.Error("this too", String("key", "value"))
}

func TestConfigureDevelopmentLogger_ValidLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		_, err := ConfigureDevelopmentLogger(context.Background(), level)
		if err != nil {
			t.Errorf("level %q should be valid, got error: %v", level, err)
		}
	}
}

func TestConfigureDevelopmentLogger_InvalidLevel(t *testing.T) {
	_, err := ConfigureDevelopmentLogger(context.Background(), "invalid")
	if err == nil {
		t.Error("expected error for invalid log level")
	}
}

func TestFieldConstructors(t *testing.T) {
	// Verify field constructors don't panic and produce fields
	_ = String("key", "val")
	_ = Int("key", 1)
	_ = Err(nil)
	_ = Any("key", struct{}{})
	_ = Strings("key", []string{"a", "b"})
}

func TestLogsGoToStderr_NotStdout(t *testing.T) {
	// Capture stdout to verify logs don't appear there
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	ctx, err := ConfigureDevelopmentLogger(context.Background(), "debug")
	if err != nil {
		os.Stdout = origStdout
		t.Fatalf("unexpected error: %v", err)
	}

	L(ctx).Info("should go to stderr not stdout")

	w.Close()
	var buf bytes.Buffer
	buf.ReadFrom(r)
	os.Stdout = origStdout

	if buf.Len() > 0 {
		t.Errorf("expected no output on stdout, got: %s", buf.String())
	}
}
