package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/qtls"
)

// oneShotMaybeRangeDownload performs a range-sliced GET directly to stdout when the upstream resource
// is large enough to risk exceeding the server's fixed response read limit.
//
// Returns:
//   - hdrs: response headers from a HEAD (preferred) or the initial range probe
//   - lastByte: last byte written to stdout (0 when no bytes were written)
//   - ok: true when slicing was used (and bytes were written)
//   - err: only set for hard failures (crypto/protocol issues, write failures, upstream failure)
func oneShotMaybeRangeDownload(
	ctx context.Context,
	log *slog.Logger,
	prov crypto.Provider,
	keys qtls.Keys,
	mode crypto.Mode,
	hc *http.Client,
	serverURL string,
	path string,
	hdrs map[string]string,
	chunkThreshold int,
	chunkSize int,
) (outHdrs map[string]string, lastByte byte, ok bool, err error) {
	// Ensure deterministic sizing behaviour; Range with compression is unreliable.
	setHeaderCI(hdrs, "Accept-Encoding", "identity")

	// Prefer HEAD to learn size cheaply.
	head, headErr := sendOneShot(ctx, log, prov, keys, mode, hc, serverURL, "", http.MethodHead, path, hdrs, nil)
	if headErr == nil && head.Status >= 200 && head.Status <= 399 {
		cl, clOK := contentLengthCI(head.Headers)
		if clOK {
			// If it is small, single request is fine.
			if cl <= int64(chunkThreshold) {
				return head.Headers, 0, false, nil
			}
			// If it is large and bytes ranges are declared, slice.
			if acceptsBytesRanges(head.Headers) {
				last, werr := rangeSliceToStdout(ctx, log, prov, keys, mode, hc, serverURL, path, hdrs, cl, chunkSize, 0, nil)
				if werr != nil {
					return nil, 0, false, werr
				}
				return head.Headers, last, true, nil
			}
		}
	}

	// Probe with a minimal range request to confirm support and recover size.
	probeHdrs := cloneHeaderMap(hdrs)
	setHeaderCI(probeHdrs, "Range", "bytes=0-0")
	probe, probeErr := sendOneShot(ctx, log, prov, keys, mode, hc, serverURL, "", http.MethodGet, path, probeHdrs, nil)
	if probeErr != nil {
		// Fall back to one-shot; caller will retry.
		return nil, 0, false, nil
	}
	if probe.Status != http.StatusPartialContent {
		// Upstream does not honour Range; single request is the only option.
		return probe.Headers, 0, false, nil
	}
	total, totalOK := totalSizeFromContentRangeCI(probe.Headers)
	if !totalOK {
		return probe.Headers, 0, false, nil
	}
	if total <= int64(chunkThreshold) {
		return probe.Headers, 0, false, nil
	}

	// We already fetched byte 0; reuse it, then continue from byte 1.
	var prefix []byte
	if len(probe.Body) == 1 {
		prefix = probe.Body
		lastByte = probe.Body[0]
	} else if len(probe.Body) > 0 {
		// Defensive: still safe to reuse; keep it simple.
		prefix = probe.Body
		lastByte = probe.Body[len(probe.Body)-1]
	}
	if len(prefix) > 0 {
		if _, werr := os.Stdout.Write(prefix); werr != nil {
			return nil, 0, false, werr
		}
	}

	last, werr := rangeSliceToStdout(ctx, log, prov, keys, mode, hc, serverURL, path, hdrs, total, chunkSize, int64(len(prefix)), prefix)
	if werr != nil {
		return nil, 0, false, werr
	}
	if last != 0 {
		lastByte = last
	}
	return probe.Headers, lastByte, true, nil
}

func rangeSliceToStdout(
	ctx context.Context,
	log *slog.Logger,
	prov crypto.Provider,
	keys qtls.Keys,
	mode crypto.Mode,
	hc *http.Client,
	serverURL string,
	path string,
	hdrs map[string]string,
	total int64,
	chunkSize int,
	startAt int64,
	_ []byte,
) (lastByte byte, err error) {
	if total <= 0 {
		return 0, fmt.Errorf("invalid content length")
	}
	if chunkSize <= 0 {
		return 0, fmt.Errorf("invalid chunk size")
	}

	var last byte
	start := startAt
	for start < total {
		end := start + int64(chunkSize) - 1
		if end >= total {
			end = total - 1
		}

		rHdrs := cloneHeaderMap(hdrs)
		setHeaderCI(rHdrs, "Accept-Encoding", "identity")
		setHeaderCI(rHdrs, "Range", fmt.Sprintf("bytes=%d-%d", start, end))

		part, reqErr := sendOneShot(ctx, log, prov, keys, mode, hc, serverURL, "", http.MethodGet, path, rHdrs, nil)
		if reqErr != nil {
			return 0, reqErr
		}

		// The expected result for a ranged fetch is 206; treat 200 as "ignored Range".
		if part.Status != http.StatusPartialContent {
			return 0, fmt.Errorf("range request not honoured; status=%d", part.Status)
		}

		expected := int(end-start) + 1
		if len(part.Body) != expected {
			return 0, fmt.Errorf("range length mismatch; expected=%d got=%d", expected, len(part.Body))
		}

		if len(part.Body) > 0 {
			if _, werr := os.Stdout.Write(part.Body); werr != nil {
				return 0, werr
			}
			last = part.Body[len(part.Body)-1]
		}

		start = end + 1
	}
	return last, nil
}

func cloneHeaderMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func headerValueCI(h map[string]string, name string) (string, bool) {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

func setHeaderCI(h map[string]string, name, value string) {
	for k := range h {
		if strings.EqualFold(k, name) {
			h[k] = value
			return
		}
	}
	h[name] = value
}

func contentLengthCI(h map[string]string) (int64, bool) {
	v, ok := headerValueCI(h, "Content-Length")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func acceptsBytesRanges(h map[string]string) bool {
	v, ok := headerValueCI(h, "Accept-Ranges")
	if !ok {
		return false
	}
	return strings.Contains(strings.ToLower(v), "bytes")
}

func totalSizeFromContentRangeCI(h map[string]string) (int64, bool) {
	v, ok := headerValueCI(h, "Content-Range")
	if !ok {
		return 0, false
	}
	v = strings.TrimSpace(v)
	// Examples:
	//   bytes 0-0/71303168
	//   bytes */71303168
	slash := strings.LastIndexByte(v, '/')
	if slash < 0 || slash+1 >= len(v) {
		return 0, false
	}
	totalStr := strings.TrimSpace(v[slash+1:])
	if totalStr == "*" {
		return 0, false
	}
	n, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func shouldAppendNewlineToTTY(lastByte byte) bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	if (fi.Mode() & os.ModeCharDevice) == 0 {
		return false
	}
	return lastByte != '\n'
}
