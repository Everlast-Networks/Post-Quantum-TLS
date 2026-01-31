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

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/example/qtls/internal/banner"
	"github.com/example/qtls/internal/certinfo"
	"github.com/example/qtls/internal/config"
	"github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/crypto/app"
	"github.com/example/qtls/internal/crypto/openssl"
	"github.com/example/qtls/internal/envelope"
	"github.com/example/qtls/internal/keyimport"
	"github.com/example/qtls/internal/logx"
	"github.com/example/qtls/internal/qtls"
	"github.com/example/qtls/internal/replay"
)

// Build can be set at build time; for example:
//
//	go build -ldflags "-X main.Build=V2601 OPEN-SOURCE EVERLAST NETWORKS PTY LTD" ...
var Build = "dev"

func main() {
	var (
		cfgPath       = flag.String("config", "./config/server.yaml", "server config path")
		debug         = flag.Bool("debug", false, "debug logging and chain print")
		logPath       = flag.String("log", "", "log path; default stderr")
		disableBanner = flag.Bool("disable-banner", false, "disable the human-readable startup banner")
	)
	flag.Parse()

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	l, closeFn, err := logx.New(logx.Options{Debug: *debug, LogPath: *logPath, Service: "qtls-server"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer closeFn()

	mode, err := crypto.ModeFromString(string(cfg.Mode))
	if err != nil {
		l.Error("bad_mode", slog.Any("err", err))
		os.Exit(2)
	}

	opensslCmd := ""
	if mode == crypto.ModeOpenSSL {
		opensslCmd = config.ResolveOpenSSLCommand(cfg.OpenSSL.Dir, cfg.OpenSSL.Command)
		if cfg.OpenSSL.ConfPath != "" {
			_ = os.Setenv("OPENSSL_CONF", cfg.OpenSSL.ConfPath)
		}
	}

	// Fast validity gate without relying on crypto/x509 algorithm tables.
	certGuard := certinfo.NewCertGuard(cfg.CertsDir, []string{
		cfg.X509.ServerCertPath,
		cfg.X509.ClientCertPath,
		cfg.X509.RootCertPath,
		cfg.X509.ChainCertPath,
	}, 30*time.Second)
	if err := certGuard.CheckNow(time.Now()); err != nil {
		l.Error("cert_invalid", slog.Any("err", err))
		os.Exit(2)
	}

	if err := verifyServerChains(context.Background(), mode, opensslCmd, cfg, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if !*disableBanner {
		banner.Print(os.Stderr, banner.Startup{
			Service:    "qtls-server",
			Build:      Build,
			Mode:       string(cfg.Mode),
			ListenAddr: cfg.Listen,
			Upstream:   cfg.Upstream,
			CertsDir:   cfg.CertsDir,
			Schemes:    banner.GuessSchemes(cfg.Keys.KEMPublicPath, cfg.Keys.SigPublicPath),
		})
	}

	if *debug && *disableBanner {
		infos, _ := certinfo.ReadChain(cfg.CertsDir)
		for _, ii := range infos {
			l.Info("cert_chain", slog.String("info", ii.String()))
		}
	}

	prov, err := buildProvider(mode, cfg.OpenSSL.Dir, cfg.OpenSSL.Command)
	if err != nil {
		l.Error("provider", slog.Any("err", err))
		os.Exit(2)
	}

	keys, err := loadServerKeys(context.Background(), mode, opensslCmd, cfg)
	if err != nil {
		l.Error("keys", slog.Any("err", err))
		os.Exit(2)
	}

	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		l.Error("upstream", slog.Any("err", err))
		os.Exit(2)
	}

	rp := replay.New(time.Duration(cfg.ReplayTTLSeconds)*time.Second, cfg.ReplayMaxEntries)
	uploads := newUploadStore(l, 30*time.Minute)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("/qtls", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/octet-stream") {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}

		if err := certGuard.CheckNow(time.Now()); err != nil {
			http.Error(w, "certificate invalid", http.StatusForbidden)
			return
		}

		b, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}

		var msg envelope.Message
		if err := msg.UnmarshalBinary(b); err != nil {
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		if msg.Header.Kind != envelope.KindRequest {
			http.Error(w, "bad kind", http.StatusBadRequest)
			return
		}
		if msg.Header.Mode != uint8(mode) {
			http.Error(w, "mode mismatch", http.StatusBadRequest)
			return
		}

		hb, err := msg.Header.MarshalBinary()
		if err != nil {
			http.Error(w, "bad header", http.StatusBadRequest)
			return
		}
		rid, err := qtls.ReadRequestIDFromHeaderBytes(hb)
		if err != nil {
			http.Error(w, "bad replay id", http.StatusBadRequest)
			return
		}
		now := logx.NowMilli()
		ts, err := qtls.ReadTimestampFromHeaderBytes(hb)
		if err != nil {
			http.Error(w, "bad timestamp", http.StatusBadRequest)
			return
		}
		if err := qtls.ValidateTimestampSkew(ts, int64((time.Duration(cfg.ReplayTTLSeconds) * time.Second).Milliseconds()), now); err != nil {
			http.Error(w, "timestamp rejected", http.StatusBadRequest)
			return
		}
		if rp.SeenBefore(rid, now) {
			http.Error(w, "replay rejected", http.StatusConflict)
			return
		}

		pl, err := qtls.OpenRequest(ctx, qtls.Options{Provider: prov}, keys, msg)
		if err != nil {
			http.Error(w, "decrypt/verify failed", http.StatusBadRequest)
			return
		}

		if msg.Header.Path == internalUploadInit || msg.Header.Path == internalUploadChunk || msg.Header.Path == internalUploadFinal || msg.Header.Path == internalUploadAbort {
			rmsg, err := handleInternalUpload(ctx, uploads, prov, keys, mode, upstream, pl, msg)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			rb, err := rmsg.MarshalBinary()
			if err != nil {
				http.Error(w, "marshal failed", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(200)
			_, _ = w.Write(rb)
			return
		}

		upURL := *upstream
		upURL.Path = msg.Header.Path
		upURL.RawQuery = r.URL.RawQuery

		upReq, err := http.NewRequestWithContext(ctx, msg.Header.Method, upURL.String(), bytes.NewReader(pl.Body))
		if err != nil {
			http.Error(w, "upstream request failed", http.StatusBadGateway)
			return
		}
		for k, v := range pl.Headers {
			upReq.Header.Set(k, v)
		}

		upClient := &http.Client{
			Timeout: 0,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
				DialContext:     (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			},
		}

		upResp, err := upClient.Do(upReq)
		if err != nil {
			http.Error(w, "upstream failed", http.StatusBadGateway)
			return
		}
		defer upResp.Body.Close()

		upBody, err := io.ReadAll(io.LimitReader(upResp.Body, 32<<20))
		if err != nil {
			http.Error(w, "upstream read failed", http.StatusBadGateway)
			return
		}

		respHdrs := make(map[string]string, len(upResp.Header))
		for k, vv := range upResp.Header {
			if len(vv) == 0 {
				continue
			}
			respHdrs[k] = vv[0]
		}

		rmsg, err := qtls.SealResponse(ctx, qtls.Options{Provider: prov}, keys, mode, upResp.StatusCode, respHdrs, upBody, msg.Header.ReplayID)
		if err != nil {
			http.Error(w, "encrypt/sign failed", http.StatusInternalServerError)
			return
		}
		rb, err := rmsg.MarshalBinary()
		if err != nil {
			http.Error(w, "marshal failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(200)
		_, _ = w.Write(rb)
	})

	srv := &http.Server{
		Addr:         cfg.Listen,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}

	l.Info("listening", slog.String("addr", cfg.Listen), slog.String("mode", mode.String()), slog.String("upstream", cfg.Upstream))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		l.Error("server", slog.Any("err", err))
		os.Exit(1)
	}
}

func verifyServerChains(ctx context.Context, mode crypto.Mode, opensslCmd string, cfg config.ServerConfig, now time.Time) error {
	if mode == crypto.ModeOpenSSL {
		vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()

		if err := certinfo.VerifyChainOpenSSL(vctx, opensslCmd, cfg.OpenSSL.ConfPath, cfg.X509.ServerCertPath, cfg.X509.RootCertPath, cfg.X509.ChainCertPath, certinfo.VerifyPurposeServer, "", now); err != nil {
			return fmt.Errorf("server certificate chain invalid: %w", err)
		}
		if err := certinfo.VerifyChainOpenSSL(vctx, opensslCmd, cfg.OpenSSL.ConfPath, cfg.X509.ClientCertPath, cfg.X509.RootCertPath, cfg.X509.ChainCertPath, certinfo.VerifyPurposeClient, "", now); err != nil {
			return fmt.Errorf("client certificate chain invalid: %w", err)
		}
		return nil
	}

	if err := verifyChainGoPaths(cfg.X509.ServerCertPath, cfg.X509.RootCertPath, cfg.X509.ChainCertPath, now, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}); err != nil {
		return fmt.Errorf("server certificate chain invalid: %w", err)
	}
	if err := verifyChainGoPaths(cfg.X509.ClientCertPath, cfg.X509.RootCertPath, cfg.X509.ChainCertPath, now, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}); err != nil {
		return fmt.Errorf("client certificate chain invalid: %w", err)
	}
	return nil
}

func verifyChainGoPaths(leafPath, rootPath, chainPath string, now time.Time, eku []x509.ExtKeyUsage) error {
	leafDER, err := readFirstCertDER(leafPath)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	if err := appendPEM(roots, rootPath); err != nil {
		return err
	}

	inters := x509.NewCertPool()
	if strings.TrimSpace(chainPath) != "" {
		if err := appendPEM(inters, chainPath); err != nil {
			return err
		}
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     eku,
	})
	return err
}

func appendPEM(pool *x509.CertPool, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if ok := pool.AppendCertsFromPEM(b); !ok {
		return fmt.Errorf("no certs parsed from %s", path)
	}
	return nil
}

func readFirstCertDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in %s", path)
	}
	return blk.Bytes, nil
}

func buildProvider(mode crypto.Mode, opensslDir, overrideCmd string) (crypto.Provider, error) {
	switch mode {
	case crypto.ModeCircl:
		return app.New()
	case crypto.ModeOpenSSL:
		cmd := config.ResolveOpenSSLCommand(opensslDir, overrideCmd)
		return openssl.New(cmd), nil
	default:
		return nil, fmt.Errorf("unsupported mode: %v", mode)
	}
}

func loadServerKeys(ctx context.Context, mode crypto.Mode, opensslCmd string, cfg config.ServerConfig) (qtls.Keys, error) {
	k := cfg.Keys

	readRaw := func(path string) ([]byte, error) {
		if strings.TrimSpace(path) == "" {
			return nil, errors.New("empty key path")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return qtls.DecodeKeyBytesForMode(mode, b)
	}

	choose := func(a, b string) string {
		if strings.TrimSpace(a) != "" {
			return a
		}
		return b
	}

	kemSelfPath := choose(k.KEMPrivatePath, k.KEMSeedPath)
	sigSelfPath := choose(k.SigPrivatePath, k.SigSeedPath)

	kemPriv, err := readRaw(kemSelfPath)
	if err != nil {
		return qtls.Keys{}, err
	}
	sigPriv, err := readRaw(sigSelfPath)
	if err != nil {
		return qtls.Keys{}, err
	}
	peerKem, err := readRaw(k.KEMPublicPath)
	if err != nil {
		return qtls.Keys{}, err
	}

	var peerSig []byte
	switch {
	case strings.TrimSpace(k.SigPublicPath) != "":
		peerSig, err = readRaw(k.SigPublicPath)
		if err != nil {
			return qtls.Keys{}, err
		}
	case mode == crypto.ModeOpenSSL:
		if opensslCmd == "" {
			opensslCmd = "openssl"
		}
		peerSig, err = certinfo.ExtractCertPublicKeyOpenSSL(ctx, opensslCmd, cfg.OpenSSL.ConfPath, cfg.X509.ClientCertPath)
		if err != nil {
			return qtls.Keys{}, err
		}
	default:
		return qtls.Keys{}, errors.New("sig_public_path is required for non-OpenSSL modes")
	}

	if mode != crypto.ModeOpenSSL {
		if kemSelfPath == k.KEMPrivatePath {
			if kemPriv, err = keyimport.UnwrapPrivate(kemPriv); err != nil {
				return qtls.Keys{}, err
			}
		}
		if sigSelfPath == k.SigPrivatePath {
			if sigPriv, err = keyimport.UnwrapPrivate(sigPriv); err != nil {
				return qtls.Keys{}, err
			}
		}
		if peerKem, err = keyimport.UnwrapPublic(peerKem); err != nil {
			return qtls.Keys{}, err
		}
		if peerSig, err = keyimport.UnwrapPublic(peerSig); err != nil {
			return qtls.Keys{}, err
		}
	}

	if len(kemPriv) == 0 || len(sigPriv) == 0 || len(peerKem) == 0 || len(peerSig) == 0 {
		return qtls.Keys{}, fmt.Errorf("missing keys; expected server KEM private/seed, server Sig private/seed, client KEM public, client Sig public (or client certificate)")
	}

	return qtls.Keys{
		KEMPrivateOrSeed: kemPriv,
		SigPrivateOrSeed: sigPriv,
		PeerKEMPublic:    peerKem,
		PeerSigPublic:    peerSig,
	}, nil
}
