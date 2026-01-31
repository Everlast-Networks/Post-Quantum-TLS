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

package certinfo

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertSummary is a minimal certificate view extracted from ASN.1 without relying on crypto/x509's
// signature/public key algorithm tables. This keeps it usable for certificates using non-standard
// or PQ OIDs.
type CertSummary struct {
	File      string
	Index     int // 0-based within a file; PEM chains can contain multiple certs
	Subject   string
	Issuer    string
	SerialHex string

	NotBefore time.Time
	NotAfter  time.Time
}

// NOTE: All fields used with encoding/asn1 must be exported; do not add '_' placeholders.
// These structs only capture what we need; the remaining elements are consumed via exported
// RawValue/BitString placeholders in the correct sequence order.

type certASN1 struct {
	TBS                tbsASN1
	SignatureAlgorithm asn1.RawValue
	SignatureValue     asn1.BitString
}

type tbsASN1 struct {
	Raw asn1.RawContent

	Version   asn1.RawValue `asn1:"optional,explicit,tag:0"`
	Serial    *big.Int
	Signature asn1.RawValue

	Issuer   asn1.RawValue
	Validity validityASN1
	Subject  asn1.RawValue

	SubjectPublicKeyInfo asn1.RawValue

	// Optional fields; tags are per X.509.
	IssuerUniqueID  asn1.BitString `asn1:"optional,tag:1"`
	SubjectUniqueID asn1.BitString `asn1:"optional,tag:2"`
	Extensions      asn1.RawValue  `asn1:"optional,explicit,tag:3"`
}

type validityASN1 struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// CertGuard type provides a fast, thread-safe validity gate for one or more certificate files.
// It caches parsed summaries for refreshWindow; each CheckNow is O(1) on the common path.
type CertGuard struct {
	paths         []string
	refreshWindow time.Duration

	mu        sync.Mutex
	nextCheck time.Time
	lastErr   error
	last      map[string][]CertSummary
}

// NewCertGuard constructs a guard for certificate files under certsDir.
// Each entry in relOrAbsPaths may be absolute or relative to certsDir.
func NewCertGuard(certsDir string, relOrAbsPaths []string, refreshWindow time.Duration) *CertGuard {
	paths := make([]string, 0, len(relOrAbsPaths))
	for _, p := range relOrAbsPaths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			paths = append(paths, p)
			continue
		}
		paths = append(paths, filepath.Join(certsDir, p))
	}
	if refreshWindow <= 0 {
		refreshWindow = 5 * time.Second
	}
	return &CertGuard{
		paths:         paths,
		refreshWindow: refreshWindow,
		last:          make(map[string][]CertSummary),
	}
}

// CheckNow validates that every parsed certificate in the configured files is currently valid.
// Missing files are ignored to avoid breaking deployments that delegate TLS to a front proxy
// and only ship some artefacts.
func (g *CertGuard) CheckNow(now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}

	g.mu.Lock()
	if now.Before(g.nextCheck) {
		err := g.lastErr
		g.mu.Unlock()
		return err
	}
	g.mu.Unlock()

	next := now.Add(g.refreshWindow)

	var firstErr error
	results := make(map[string][]CertSummary, len(g.paths))

	for _, p := range g.paths {
		sums, err := readCertSummaries(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				results[p] = nil
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p, err)
			}
			results[p] = nil
			continue
		}

		for _, s := range sums {
			if now.Before(s.NotBefore) || !now.Before(s.NotAfter) {
				if firstErr == nil {
					firstErr = fmt.Errorf("%s[%d]: outside validity window (not_before=%s not_after=%s)",
						filepath.Base(p), s.Index, s.NotBefore.UTC().Format(time.RFC3339), s.NotAfter.UTC().Format(time.RFC3339))
				}
				break
			}
		}
		results[p] = sums
	}

	g.mu.Lock()
	g.nextCheck = next
	g.lastErr = firstErr
	g.last = results
	g.mu.Unlock()

	return firstErr
}

// Summaries returns the last parsed summaries; intended for diagnostics.
func (g *CertGuard) Summaries() map[string][]CertSummary {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string][]CertSummary, len(g.last))
	for k, v := range g.last {
		cp := make([]CertSummary, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

func readCertSummaries(path string) ([]CertSummary, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// PEM: extract all CERTIFICATE blocks.
	if bytes.Contains(b, []byte("-----BEGIN")) {
		var out []CertSummary
		rest := b
		idx := 0
		for {
			blk, r := pem.Decode(rest)
			if blk == nil {
				break
			}
			rest = r
			if blk.Type != "CERTIFICATE" {
				continue
			}
			s, err := parseCertDER(blk.Bytes)
			if err != nil {
				return nil, err
			}
			s.File = path
			s.Index = idx
			out = append(out, s)
			idx++
		}
		if len(out) == 0 {
			return nil, errors.New("no certificate blocks found")
		}
		return out, nil
	}

	// DER: single certificate.
	s, err := parseCertDER(b)
	if err != nil {
		return nil, err
	}
	s.File = path
	s.Index = 0
	return []CertSummary{s}, nil
}

func parseCertDER(der []byte) (CertSummary, error) {
	var cert certASN1
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return CertSummary{}, err
	}

	subj, _ := decodeName(cert.TBS.Subject)
	iss, _ := decodeName(cert.TBS.Issuer)

	serialHex := ""
	if cert.TBS.Serial != nil {
		serialHex = strings.ToLower(hex.EncodeToString(cert.TBS.Serial.Bytes()))
	}

	return CertSummary{
		Subject:   subj,
		Issuer:    iss,
		SerialHex: serialHex,
		NotBefore: cert.TBS.Validity.NotBefore,
		NotAfter:  cert.TBS.Validity.NotAfter,
	}, nil
}

func decodeName(raw asn1.RawValue) (string, error) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(raw.FullBytes, &rdn); err != nil {
		return "", err
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String(), nil
}
