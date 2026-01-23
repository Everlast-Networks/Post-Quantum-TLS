package logx

import (
	"context"
	"log/slog"
	"os"
	"time"
)

type Options struct {
	Debug   bool
	LogPath string
	Service string
}

func New(opts Options) (*slog.Logger, func() error, error) {
	var (
		out     *os.File
		closeFn func() error
	)
	if opts.LogPath == "" {
		out = os.Stderr
		closeFn = func() error { return nil }
	} else {
		f, err := os.OpenFile(opts.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, nil, err
		}
		out = f
		closeFn = f.Close
	}

	lvl := slog.LevelInfo
	if opts.Debug {
		lvl = slog.LevelDebug
	}
	h := slog.NewJSONHandler(out, &slog.HandlerOptions{
		Level: lvl,
	})
	l := slog.New(h).With(
		slog.String("service", opts.Service),
		slog.String("ts_unit", "ms"),
	)
	slog.SetDefault(l)
	return l, closeFn, nil
}

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestID{}, id)
}

func RequestID(ctx context.Context) string {
	if v := ctx.Value(ctxKeyRequestID{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

type ctxKeyRequestID struct{}

func NowMilli() int64 { return time.Now().UTC().UnixMilli() }
