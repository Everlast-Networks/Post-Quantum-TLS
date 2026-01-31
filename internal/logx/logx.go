// ---------------------------------------------------------------------------
// Copyright (c) 2026 Everlast Networks Pty. Ltd..
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" basis,
// without warranties or conditions of any kind, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ---------------------------------------------------------------------------

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
