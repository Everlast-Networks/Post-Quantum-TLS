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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// VerifyChainNow is a convenience wrapper that resolves filenames under certsDir.
func VerifyChainNow(
	certsDir string,
	leafName string,
	rootName string,
	chainName string,
	now time.Time,
	eku []x509.ExtKeyUsage,
) error {
	leafPath := filepath.Join(certsDir, leafName)
	rootPath := filepath.Join(certsDir, rootName)
	chainPath := filepath.Join(certsDir, chainName)
	return VerifyChainPathsNow(leafPath, rootPath, chainPath, now, eku)
}

// VerifyChainPathsNow verifies a leaf certificate against the supplied trust roots and intermediates,
// using the Go x509 verifier. Suitable for classical chains; PQ chains should use VerifyChainOpenSSLNow.
func VerifyChainPathsNow(
	leafCertPath string,
	rootCertPath string,
	chainCertPath string,
	now time.Time,
	eku []x509.ExtKeyUsage,
) error {
	leafDER, err := readFirstCertDER(leafCertPath)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	if err := appendPEM(roots, rootCertPath); err != nil {
		return err
	}

	inters := x509.NewCertPool()
	if chainCertPath != "" {
		if err := appendPEM(inters, chainCertPath); err != nil {
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
