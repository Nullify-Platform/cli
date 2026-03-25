package logger

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Version is set at build time via ldflags.
var Version string

// Field is a type alias for zap.Field so callers use logger.Field transparently.
type Field = zap.Field

// Logger wraps a *zap.Logger.
type Logger struct {
	*zap.Logger
}

type ctxKey struct{}

// ConfigureDevelopmentLogger creates a zap development logger at the given level,
// stores it in the returned context, and returns the context.
// Logs are written to stderr so they don't corrupt piped stdout output.
func ConfigureDevelopmentLogger(ctx context.Context, logLevel string) (context.Context, error) {
	level, err := zapcore.ParseLevel(logLevel)
	if err != nil {
		return ctx, err
	}

	cfg := zap.NewDevelopmentConfig()
	cfg.Level = zap.NewAtomicLevelAt(level)
	cfg.OutputPaths = []string{"stderr"}
	cfg.ErrorOutputPaths = []string{"stderr"}

	zapLogger, err := cfg.Build()
	if err != nil {
		return ctx, err
	}

	return context.WithValue(ctx, ctxKey{}, &Logger{zapLogger}), nil
}

// L retrieves the logger from context. Returns a no-op logger if none is set.
func L(ctx context.Context) *Logger {
	if l, ok := ctx.Value(ctxKey{}).(*Logger); ok {
		return l
	}
	return &Logger{zap.NewNop()}
}

// Close flushes the logger, ignoring the sync error that is expected
// on stderr-based loggers (see https://github.com/uber-go/zap/issues/880).
func Close(ctx context.Context) {
	_ = L(ctx).Sync()
}

// Field constructors

func String(key, val string) Field           { return zap.String(key, val) }
func Int(key string, val int) Field          { return zap.Int(key, val) }
func Err(err error) Field                    { return zap.Error(err) }
func Any(key string, val any) Field          { return zap.Any(key, val) }
func Strings(key string, val []string) Field { return zap.Strings(key, val) }
