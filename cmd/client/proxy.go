package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/example/qtls/internal/certinfo"
	"github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/qtls"
)

const (
	internalUploadInit  = "/__qtls/internal/upload/init"
	internalUploadChunk = "/__qtls/internal/upload/chunk"
	internalUploadFinal = "/__qtls/internal/upload/final"
	internalUploadAbort = "/__qtls/internal/upload/abort"

	hdrTransferID = "X-QTLS-Transfer-ID"
	hdrChunkIndex = "X-QTLS-Chunk-Index"
	hdrChunkSHA   = "X-QTLS-Chunk-SHA256"

	hdrUpMethod     = "X-QTLS-Upstream-Method"
	hdrUpPath       = "X-QTLS-Upstream-Path"
	hdrUpQuery      = "X-QTLS-Upstream-Query"
	hdrUpHeadersB64 = "X-QTLS-Upstream-Headers-B64"
)

type proxy struct {
	certGuard      *certinfo.CertGuard
	log            *slog.Logger
	prov           crypto.Provider
	keys           qtls.Keys
	mode           crypto.Mode
	hc             *http.Client
	serverURL      string
	chunkThreshold int
	chunkSize      int
	timeout        time.Duration
}

func (p proxy) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/", p.handle)
	return mux
}

func (p proxy) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
		return
	}

	if p.certGuard != nil {
		if err := p.certGuard.CheckNow(time.Now()); err != nil {
			http.Error(w, "certificate invalid", http.StatusForbidden)
			return
		}
	}

	if p.isChunkedUploadCandidate(r) {
		p.handleChunkedUpload(w, r)
		return
	}

	if p.isRangeSlicingCandidate(r) {
		if ok := p.handleRangeSlicedDownload(w, r); ok {
			return
		}
		// Fall through to one-shot.
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}

	hdrs := p.inboundHeaders(r)
	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()

	resp, err := sendOneShot(ctx, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, r.URL.RawQuery, r.Method, r.URL.Path, hdrs, body)
	if err != nil {
		http.Error(w, "upstream failed", http.StatusBadGateway)
		return
	}

	p.writeResponse(w, resp)
}

func (p proxy) isChunkedUploadCandidate(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	if r.Body == nil {
		return false
	}
	// Unknown length or larger than threshold.
	return r.ContentLength < 0 || r.ContentLength > int64(p.chunkThreshold)
}

func (p proxy) isRangeSlicingCandidate(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	// If the caller already uses Range, pass through unmodified.
	if r.Header.Get("Range") != "" {
		return false
	}
	return true
}

func (p proxy) handleChunkedUpload(w http.ResponseWriter, r *http.Request) {
	// Clients that send Expect: 100-continue can withhold the body until the server
	// starts reading it. net/http emits 100 Continue automatically on the first read
	// when Expect: 100-continue is present.
	//
	// We pre-read up to one chunk before doing upstream work; this avoids a fast upstream
	// final response racing ahead of the client body send and turning the upload into
	// an empty-body request.
	br := bufio.NewReaderSize(r.Body, p.chunkSize)
	buf := make([]byte, p.chunkSize)

	n0, err0 := br.Read(buf)
	if err0 != nil && err0 != io.EOF {
		http.Error(w, "read failed", http.StatusBadRequest)
		return
	}
	if n0 == 0 && err0 == io.EOF {
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}
	firstChunk := make([]byte, n0)
	copy(firstChunk, buf[:n0])

	transferID, err := newTransferID()
	if err != nil {
		http.Error(w, "transfer id", http.StatusInternalServerError)
		return
	}

	inHdrs := p.inboundHeaders(r)
	meta, err := json.Marshal(inHdrs)
	if err != nil {
		http.Error(w, "header marshal", http.StatusInternalServerError)
		return
	}
	metaB64 := base64.StdEncoding.EncodeToString(meta)

	initHdrs := map[string]string{
		hdrTransferID:   transferID,
		hdrUpMethod:     r.Method,
		hdrUpPath:       r.URL.Path,
		hdrUpQuery:      r.URL.RawQuery,
		hdrUpHeadersB64: metaB64,
	}

	ctx, cancel := context.WithTimeout(r.Context(), p.timeout)
	defer cancel()
	if _, err := sendOneShot(ctx, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, "", http.MethodPost, internalUploadInit, initHdrs, nil); err != nil {
		http.Error(w, "init failed", http.StatusBadGateway)
		return
	}

	var idx uint64

	// Send the pre-read first chunk as index 0.
	{
		sum := sha256.Sum256(firstChunk)
		chunkHdrs := map[string]string{
			hdrTransferID: transferID,
			hdrChunkIndex: strconv.FormatUint(idx, 10),
			hdrChunkSHA:   hex.EncodeToString(sum[:]),
		}
		ctxChunk0, cancelChunk0 := context.WithTimeout(r.Context(), p.timeout)
		_, err := sendOneShot(ctxChunk0, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, "", http.MethodPost, internalUploadChunk, chunkHdrs, firstChunk)
		cancelChunk0()
		if err != nil {
			_ = p.abortUpload(r.Context(), transferID)
			http.Error(w, "chunk failed", http.StatusBadGateway)
			return
		}
		idx++
	}

	for {
		n, readErr := io.ReadFull(br, buf)
		if readErr == io.ErrUnexpectedEOF {
			// Final partial chunk.
		} else if readErr == io.EOF {
			break
		} else if readErr != nil && readErr != io.ErrUnexpectedEOF {
			_ = p.abortUpload(r.Context(), transferID)
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}

		chunk := buf[:n]
		sum := sha256.Sum256(chunk)
		chunkHdrs := map[string]string{
			hdrTransferID: transferID,
			hdrChunkIndex: strconv.FormatUint(idx, 10),
			hdrChunkSHA:   hex.EncodeToString(sum[:]),
		}

		ctxChunk, cancelChunk := context.WithTimeout(r.Context(), p.timeout)
		reqErr := func() error {
			defer cancelChunk()
			_, err := sendOneShot(ctxChunk, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, "", http.MethodPost, internalUploadChunk, chunkHdrs, chunk)
			return err
		}()
		if reqErr != nil {
			_ = p.abortUpload(r.Context(), transferID)
			http.Error(w, "chunk failed", http.StatusBadGateway)
			return
		}
		idx++

		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}

	ctxFinal, cancelFinal := context.WithTimeout(r.Context(), p.timeout)
	defer cancelFinal()
	finalHdrs := map[string]string{hdrTransferID: transferID}
	resp, err := sendOneShot(ctxFinal, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, "", http.MethodPost, internalUploadFinal, finalHdrs, nil)
	if err != nil {
		http.Error(w, "final failed", http.StatusBadGateway)
		return
	}

	p.writeResponse(w, resp)
}

func (p proxy) abortUpload(ctx context.Context, transferID string) error {
	ctxAbort, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	_, err := sendOneShot(ctxAbort, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, "", http.MethodPost, internalUploadAbort, map[string]string{hdrTransferID: transferID}, nil)
	return err
}

func (p proxy) handleRangeSlicedDownload(w http.ResponseWriter, r *http.Request) bool {
	hdrs := p.inboundHeaders(r)
	// Make metadata probes cheap and deterministic: avoid compressed representations affecting lengths.
	delete(hdrs, "Accept-Encoding")

	var metaHeaders map[string]string
	var totalLen int64
	haveRange := false

	// Prefer HEAD for representation metadata.
	ctxHead, cancelHead := context.WithTimeout(r.Context(), p.timeout)
	head, headErr := sendOneShot(ctxHead, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, r.URL.RawQuery, http.MethodHead, r.URL.Path, hdrs, nil)
	cancelHead()
	if headErr == nil && head.Status >= 200 && head.Status <= 399 {
		metaHeaders = head.Headers
		if clStr, ok := head.Headers["Content-Length"]; ok {
			if cl, err := strconv.ParseInt(strings.TrimSpace(clStr), 10, 64); err == nil && cl > 0 {
				totalLen = cl
			}
		}
		ar := strings.ToLower(head.Headers["Accept-Ranges"])
		if strings.Contains(ar, "bytes") {
			haveRange = true
		}
	}

	// Fallback: some upstreams emit invalid/missing Content-Length on HEAD. Probe with a cheap ranged GET.
	if totalLen <= 0 || !haveRange {
		probeHdrs := make(map[string]string, len(hdrs)+1)
		for k, v := range hdrs {
			probeHdrs[k] = v
		}
		probeHdrs["Range"] = "bytes=0-0"

		ctxProbe, cancelProbe := context.WithTimeout(r.Context(), p.timeout)
		probe, err := sendOneShot(ctxProbe, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, r.URL.RawQuery, http.MethodGet, r.URL.Path, probeHdrs, nil)
		cancelProbe()
		if err != nil {
			return false
		}

		switch probe.Status {
		case http.StatusPartialContent:
			// 206 implies Range support; parse total length from Content-Range.
			haveRange = true
			if metaHeaders == nil {
				metaHeaders = probe.Headers
			}
			if totalLen <= 0 {
				if tl, ok := parseContentRangeTotal(probe.Headers["Content-Range"]); ok {
					totalLen = tl
				}
			}
		case http.StatusRequestedRangeNotSatisfiable:
			// For 416, Content-Range is expected to be of the form "bytes */<length>".
			if tl, ok := parseContentRangeTotal(probe.Headers["Content-Range"]); ok {
				totalLen = tl
			}
			return false
		case http.StatusOK:
			// Upstream ignored Range; slicing would duplicate data.
			return false
		default:
			return false
		}
	}

	if totalLen <= int64(p.chunkThreshold) {
		return false
	}
	if metaHeaders == nil || !haveRange {
		return false
	}

	for k, v := range metaHeaders {
		if isHopByHopHeader(k) {
			continue
		}
		// We are synthesising a 200 response body from multiple 206s.
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Content-Range") {
			continue
		}
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(totalLen, 10))
	w.WriteHeader(http.StatusOK)

	fl, _ := w.(http.Flusher)
	var start int64
	for start < totalLen {
		end := start + int64(p.chunkSize) - 1
		if end >= totalLen {
			end = totalLen - 1
		}

		rHdrs := make(map[string]string, len(hdrs)+1)
		for k, v := range hdrs {
			rHdrs[k] = v
		}
		rHdrs["Range"] = fmt.Sprintf("bytes=%d-%d", start, end)

		ctxGet, cancelGet := context.WithTimeout(r.Context(), p.timeout)
		part, err := sendOneShot(ctxGet, p.log, p.prov, p.keys, p.mode, p.hc, p.serverURL, r.URL.RawQuery, http.MethodGet, r.URL.Path, rHdrs, nil)
		cancelGet()
		if err != nil {
			return true
		}
		if part.Status != http.StatusPartialContent {
			// If the upstream stops honouring Range, continuing would corrupt the stream.
			return true
		}
		expected := end - start + 1
		if int64(len(part.Body)) != expected {
			return true
		}

		_, _ = w.Write(part.Body)
		if fl != nil {
			fl.Flush()
		}
		start = end + 1
	}

	return true
}

func (p proxy) inboundHeaders(r *http.Request) map[string]string {
	out := make(map[string]string, len(r.Header))
	for k, vv := range r.Header {
		if len(vv) == 0 {
			continue
		}
		if isHopByHopHeader(k) {
			continue
		}
		out[k] = vv[0]
	}
	// "Expect: 100-continue" can stall uploads when forwarded to an upstream that
	// does not actively participate in the handshake. The proxy handles the
	// inbound Expect locally.
	delete(out, "Expect")
	// Avoid confused deputy issues.
	delete(out, hdrTransferID)
	delete(out, hdrChunkIndex)
	delete(out, hdrChunkSHA)
	delete(out, hdrUpMethod)
	delete(out, hdrUpPath)
	delete(out, hdrUpQuery)
	delete(out, hdrUpHeadersB64)
	return out
}

func (p proxy) writeContinueIfRequested(w http.ResponseWriter, r *http.Request) {
	v := strings.ToLower(strings.TrimSpace(r.Header.Get("Expect")))
	if v == "" || !strings.Contains(v, "100-continue") {
		return
	}

	// net/http permits any number of 1xx responses before a final status; issuing 100
	// early helps clients that otherwise withhold the request body until continued.
	w.WriteHeader(http.StatusContinue)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
}

func (p proxy) writeResponse(w http.ResponseWriter, resp qtlsHTTPResponse) {
	for k, v := range resp.Headers {
		if isHopByHopHeader(k) {
			continue
		}
		w.Header().Set(k, v)
	}
	if resp.Status == 0 {
		resp.Status = 200
	}
	w.WriteHeader(resp.Status)
	_, _ = w.Write(resp.Body)
}

func parseContentRangeTotal(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	lv := strings.ToLower(v)
	if !strings.HasPrefix(lv, "bytes") {
		return 0, false
	}
	parts := strings.SplitN(v, "/", 2)
	if len(parts) != 2 {
		return 0, false
	}
	totalStr := strings.TrimSpace(parts[1])
	if totalStr == "" || totalStr == "*" {
		return 0, false
	}
	total, err := strconv.ParseInt(totalStr, 10, 64)
	if err != nil || total < 0 {
		return 0, false
	}
	return total, true
}

func isHopByHopHeader(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "connection", "proxy-connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func newTransferID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
