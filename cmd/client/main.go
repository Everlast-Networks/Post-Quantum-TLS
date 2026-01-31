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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
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
	"github.com/example/qtls/internal/crypto/system"
	"github.com/example/qtls/internal/keyimport"
	"github.com/example/qtls/internal/logx"
	"github.com/example/qtls/internal/qtls"
)

// Build can be set at build time; for example...
//	go build -ldflags "-X main.Build=V2601 OPEN-SOURCE EVERLAST NETWORKS PTY LTD" ...:

var Build = "dev"

type headerList []string

func (h *headerList) String() string { return strings.Join(*h, ",") }
func (h *headerList) Set(v string) error {
	*h = append(*h, v)
	return nil
}

func main() {
	var (
		cfgPath   = flag.String("config", "./config/client.yaml", "client config path")
		serverURL = flag.String("server", "http://127.0.0.1:5000/qtls", "server URL, typically https://.../qtls")

		listen     = flag.Bool("listen", false, "run as a local HTTP forward proxy")
		listenAddr = flag.String("listen-addr", "127.0.0.1", "listen address for -listen")
		listenPort = flag.Int("listen-port", 7777, "listen port for -listen")

		chunkThreshold = flag.Int("chunk-threshold", 8<<20, "bytes; request bodies above this are chunk-uploaded")
		chunkSize      = flag.Int("chunk-size", 4<<20, "bytes; size for chunked uploads and range downloads")

		timeout = flag.Duration("timeout", 30*time.Second, "overall timeout for one-shot mode; server mode uses this per QTLS request")

		method  = flag.String("method", "POST", "HTTP method to tunnel to upstream")
		path    = flag.String("path", "/echo", "HTTP path to tunnel to upstream")
		message = flag.String("message", "", "payload as a string; ignored when -stdin is set")
		stdin   = flag.Bool("stdin", false, "read payload body from stdin")

		debug         = flag.Bool("debug", false, "debug logging and chain print")
		logPath       = flag.String("log", "", "log path; default stderr")
		disableBanner = flag.Bool("disable-banner", false, "disable the human-readable startup banner")

		insecureSkipVerify = flag.Bool("insecure-skip-verify", false, "skip TLS verification for transport; tests only")
	)

	var hdrs headerList
	flag.Var(&hdrs, "H", "extra header, repeatable; example: -H 'X-Foo: bar'")
	flag.Parse()

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	l, closeFn, err := logx.New(logx.Options{Debug: *debug, LogPath: *logPath, Service: "qtls-client"})
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

	if mode == crypto.ModeSystem {
		ok, why := system.Supported()
		if !ok {
			l.Error("system_mode_unavailable", slog.String("reason", why))
			os.Exit(2)
		}
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
		cfg.X509.ClientCertPath,
		cfg.X509.ServerCertPath,
		cfg.X509.RootCertPath,
		cfg.X509.ChainCertPath,
	}, 30*time.Second)
	if err := certGuard.CheckNow(time.Now()); err != nil {
		l.Error("cert_invalid", slog.Any("err", err))
		os.Exit(2)
	}

	if err := verifyClientChains(context.Background(), mode, opensslCmd, cfg, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if !*disableBanner {
		s := banner.Startup{
			Service:  "qtls-client",
			Build:    Build,
			Mode:     string(cfg.Mode),
			CertsDir: cfg.CertsDir,
			Schemes:  banner.GuessSchemes(cfg.Keys.KEMPublicPath, cfg.Keys.SigPublicPath),
		}
		if *listen {
			addr := net.JoinHostPort(*listenAddr, fmt.Sprintf("%d", *listenPort))
			s.ListenAddr = addr
			s.Upstream = *serverURL
		} else {
			s.Upstream = *serverURL
		}
		banner.Print(os.Stderr, s)
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

	keys, err := loadClientKeys(context.Background(), mode, opensslCmd, cfg)
	if err != nil {
		l.Error("keys", slog.Any("err", err))
		os.Exit(2)
	}

	if *stdin && *message != "" {
		l.Error("invalid_args", slog.String("reason", "use -stdin or -message, not both"))
		os.Exit(2)
	}

	headerMap := make(map[string]string)
	for _, hv := range hdrs {
		k, v, ok := strings.Cut(hv, ":")
		if !ok {
			l.Error("bad_header", slog.String("value", hv))
			os.Exit(2)
		}
		headerMap[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	hc := &http.Client{
		Timeout:   *timeout,
		Transport: &http.Transport{TLSClientConfig: tlsConfig(*insecureSkipVerify)},
	}

	if *listen {
		addr := net.JoinHostPort(*listenAddr, fmt.Sprintf("%d", *listenPort))
		p := proxy{
			certGuard:      certGuard,
			log:            l,
			prov:           prov,
			keys:           keys,
			mode:           mode,
			hc:             hc,
			serverURL:      *serverURL,
			chunkThreshold: *chunkThreshold,
			chunkSize:      *chunkSize,
			timeout:        *timeout,
		}
		l.Info("proxy_listen", slog.String("addr", addr))
		if err := http.ListenAndServe(addr, p.routes()); err != nil {
			l.Error("listen", slog.Any("err", err))
			os.Exit(1)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	if strings.EqualFold(*method, http.MethodGet) {
		headersForReq := cloneHeaderMap(headerMap)
		if _, ok := headerValueCI(headersForReq, "Range"); !ok {
			hdrs, lastByte, ok, err := oneShotMaybeRangeDownload(ctx, l, prov, keys, mode, hc, *serverURL, *path, headersForReq, *chunkThreshold, *chunkSize)
			if err != nil {
				l.Error("request", slog.Any("err", err))
				os.Exit(2)
			}
			if ok {
				if *debug {
					jb, _ := json.Marshal(hdrs)
					l.Debug("response_headers", slog.String("headers", string(jb)))
				}
				if shouldAppendNewlineToTTY(lastByte) {
					_, _ = os.Stdout.Write([]byte("\n"))
				}
				return
			}
		}
	}

	body, err := readBody(*stdin, *message)
	if err != nil {
		l.Error("body", slog.Any("err", err))
		os.Exit(2)
	}

	resp, err := sendOneShot(ctx, l, prov, keys, mode, hc, *serverURL, "", *method, *path, headerMap, body)
	if err != nil {
		l.Error("request", slog.Any("err", err))
		os.Exit(2)
	}

	_, _ = os.Stdout.Write(resp.Body)
	var last byte
	if len(resp.Body) > 0 {
		last = resp.Body[len(resp.Body)-1]
	}
	if shouldAppendNewlineToTTY(last) {
		_, _ = os.Stdout.Write([]byte("\n"))
	}

	if *debug {
		jb, _ := json.Marshal(resp.Headers)
		l.Debug("response_headers", slog.String("headers", string(jb)))
	}
}

func verifyClientChains(ctx context.Context, mode crypto.Mode, opensslCmd string, cfg config.ClientConfig, now time.Time) error {
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

func readBody(fromStdin bool, msg string) ([]byte, error) {
	if fromStdin {
		return io.ReadAll(os.Stdin)
	}
	return []byte(msg), nil
}

func appendRawQuery(serverURL, rawQuery string) (string, error) {
	if rawQuery == "" {
		return serverURL, nil
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	newQ, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", err
	}
	for k, vv := range newQ {
		for _, v := range vv {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func buildProvider(mode crypto.Mode, opensslDir, overrideCmd string) (crypto.Provider, error) {
	switch mode {
	case crypto.ModeCircl:
		return app.New()
	case crypto.ModeOpenSSL:
		cmd := config.ResolveOpenSSLCommand(opensslDir, overrideCmd)
		return openssl.New(cmd), nil
	case crypto.ModeSystem:
		return system.New(), nil
	default:
		return nil, fmt.Errorf("unsupported mode: %v", mode)
	}
}

func loadClientKeys(ctx context.Context, mode crypto.Mode, opensslCmd string, cfg config.ClientConfig) (qtls.Keys, error) {
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
		peerSig, err = certinfo.ExtractCertPublicKeyOpenSSL(ctx, opensslCmd, cfg.OpenSSL.ConfPath, cfg.X509.ServerCertPath)
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
		return qtls.Keys{}, fmt.Errorf("missing keys; expected client KEM private/seed, client Sig private/seed, server KEM public, server Sig public (or server certificate)")
	}

	return qtls.Keys{
		KEMPrivateOrSeed: kemPriv,
		SigPrivateOrSeed: sigPriv,
		PeerKEMPublic:    peerKem,
		PeerSigPublic:    peerSig,
	}, nil
}

func tlsConfig(skip bool) *tls.Config {
	if !skip {
		return nil
	}
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}
