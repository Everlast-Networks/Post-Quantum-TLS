package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
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

type uploadStore struct {
	mu       sync.Mutex
	log      *slog.Logger
	maxAge   time.Duration
	sessions map[string]*uploadSession
}

type uploadSession struct {
	id      string
	created time.Time
	tmpPath string
	f       *os.File
	nextIdx uint64
	method  string
	path    string
	query   string
	headers map[string]string
}

func newUploadStore(log *slog.Logger, maxAge time.Duration) *uploadStore {
	return &uploadStore{
		log:      log,
		maxAge:   maxAge,
		sessions: make(map[string]*uploadSession),
	}
}

func (s *uploadStore) cleanupLocked(now time.Time) {
	for id, ss := range s.sessions {
		if now.Sub(ss.created) <= s.maxAge {
			continue
		}
		_ = ss.f.Close()
		_ = os.Remove(ss.tmpPath)
		delete(s.sessions, id)
	}
}

func (s *uploadStore) init(plHeaders map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(time.Now())

	id := strings.TrimSpace(plHeaders[hdrTransferID])
	if id == "" {
		return errors.New("missing transfer id")
	}
	if _, ok := s.sessions[id]; ok {
		return errors.New("transfer id already exists")
	}

	method := strings.TrimSpace(plHeaders[hdrUpMethod])
	path := strings.TrimSpace(plHeaders[hdrUpPath])
	query := strings.TrimSpace(plHeaders[hdrUpQuery])
	if method == "" || path == "" {
		return errors.New("missing upstream method/path")
	}

	headers := make(map[string]string)
	if b64 := strings.TrimSpace(plHeaders[hdrUpHeadersB64]); b64 != "" {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return errors.New("bad upstream headers encoding")
		}
		if err := json.Unmarshal(raw, &headers); err != nil {
			return errors.New("bad upstream headers json")
		}
	}

	f, err := os.CreateTemp("", "qtls-upload-*")
	if err != nil {
		return err
	}

	s.sessions[id] = &uploadSession{
		id:      id,
		created: time.Now(),
		tmpPath: f.Name(),
		f:       f,
		method:  method,
		path:    path,
		query:   query,
		headers: headers,
	}

	s.log.Info("upload_init", slog.String("id", id), slog.String("tmp", f.Name()), slog.String("method", method), slog.String("path", path))
	return nil
}

func (s *uploadStore) appendChunk(plHeaders map[string]string, chunk []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(time.Now())

	id := strings.TrimSpace(plHeaders[hdrTransferID])
	ss, ok := s.sessions[id]
	if !ok {
		return errors.New("unknown transfer id")
	}

	idxStr := strings.TrimSpace(plHeaders[hdrChunkIndex])
	idx, err := strconv.ParseUint(idxStr, 10, 64)
	if err != nil {
		return errors.New("bad chunk index")
	}
	if idx != ss.nextIdx {
		return fmt.Errorf("unexpected chunk index: got %d want %d", idx, ss.nextIdx)
	}

	if want := strings.TrimSpace(plHeaders[hdrChunkSHA]); want != "" {
		sum := sha256.Sum256(chunk)
		got := hex.EncodeToString(sum[:])
		if !strings.EqualFold(got, want) {
			return errors.New("chunk hash mismatch")
		}
	}

	if _, err := ss.f.Write(chunk); err != nil {
		return err
	}
	ss.nextIdx++
	return nil
}

func (s *uploadStore) abort(plHeaders map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := strings.TrimSpace(plHeaders[hdrTransferID])
	ss, ok := s.sessions[id]
	if !ok {
		return
	}
	_ = ss.f.Close()
	_ = os.Remove(ss.tmpPath)
	delete(s.sessions, id)
	s.log.Info("upload_abort", slog.String("id", id))
}

type finalisedUpload struct {
	method  string
	path    string
	query   string
	headers map[string]string
	file    *os.File
	cleanup func()
}

func (s *uploadStore) finalise(plHeaders map[string]string) (finalisedUpload, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupLocked(time.Now())

	id := strings.TrimSpace(plHeaders[hdrTransferID])
	ss, ok := s.sessions[id]
	if !ok {
		return finalisedUpload{}, errors.New("unknown transfer id")
	}
	_ = ss.f.Close()

	f, err := os.Open(ss.tmpPath)
	if err != nil {
		return finalisedUpload{}, err
	}

	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(ss.tmpPath)
	}

	delete(s.sessions, id)
	s.log.Info("upload_final", slog.String("id", id), slog.String("tmp", ss.tmpPath))
	return finalisedUpload{
		method:  ss.method,
		path:    ss.path,
		query:   ss.query,
		headers: ss.headers,
		file:    f,
		cleanup: cleanup,
	}, nil
}

func jsonOK() []byte {
	b, _ := json.Marshal(map[string]any{"status": "ok"})
	return append(b, '\n')
}

func readAllLimited(r io.Reader, lim int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, lim))
}
