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
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	mldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	mldsa87 "github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type mldsaLevel int

const (
	mldsaL44 mldsaLevel = 44
	mldsaL65 mldsaLevel = 65
	mldsaL87 mldsaLevel = 87
)

func main() {
	var (
		outDir   = flag.String("out", "", "output directory; typically .../certs/circl")
		levelStr = flag.String("mldsa", "87", "ML-DSA level: 44|65|87")
		force    = flag.Bool("force", false, "overwrite existing files")
	)
	flag.Parse()

	if *outDir == "" {
		fatalf("missing -out")
	}

	level, err := parseLevel(*levelStr)
	if err != nil {
		fatalf("bad -mldsa: %v", err)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("mkdir: %v", err)
	}

	// KEM (fixed: ML-KEM-1024 for V1)
	kemScheme := mlkem1024.Scheme()

	// Generate full circl keyset: client + server
	if err := genKEMPair(kemScheme, *outDir, "client", *force); err != nil {
		fatalf("client kem: %v", err)
	}
	if err := genKEMPair(kemScheme, *outDir, "server", *force); err != nil {
		fatalf("server kem: %v", err)
	}

	// Generate ML-DSA keypair by chosen level
	switch level {
	case mldsaL44:
		if err := genMLDSA44(*outDir, "client", *force); err != nil {
			fatalf("client mldsa44: %v", err)
		}
		if err := genMLDSA44(*outDir, "server", *force); err != nil {
			fatalf("server mldsa44: %v", err)
		}
	case mldsaL65:
		if err := genMLDSA65(*outDir, "client", *force); err != nil {
			fatalf("client mldsa65: %v", err)
		}
		if err := genMLDSA65(*outDir, "server", *force); err != nil {
			fatalf("server mldsa65: %v", err)
		}
	case mldsaL87:
		if err := genMLDSA87(*outDir, "client", *force); err != nil {
			fatalf("client mldsa87: %v", err)
		}
		if err := genMLDSA87(*outDir, "server", *force); err != nil {
			fatalf("server mldsa87: %v", err)
		}
	default:
		fatalf("unsupported ML-DSA level: %d", level)
	}

	// Drop a short hint file for operators.
	readme := filepath.Join(*outDir, "README.txt")
	_ = writeFileAtomic(readme, 0o644, []byte(
		"QTLS Circl mode keys.\n"+
			"\n"+
			"Files:\n"+
			"  client.kem.seed   (binary seed; ML-KEM-1024)\n"+
			"  client.kem.pub    (binary packed public key)\n"+
			"  server.kem.seed\n"+
			"  server.kem.pub\n"+
			"  client.sig.seed   (binary seed; ML-DSA-44/65/87)\n"+
			"  client.sig.pub    (binary packed public key)\n"+
			"  server.sig.seed\n"+
			"  server.sig.pub\n"+
			"\n"+
			"YAML should reference seed paths for private material; public paths for peers.\n",
	), *force)

	fmt.Fprintf(os.Stdout, "ok: wrote Circl keys into %s\n", *outDir)
}

func parseLevel(s string) (mldsaLevel, error) {
	switch s {
	case "44":
		return mldsaL44, nil
	case "65":
		return mldsaL65, nil
	case "87":
		return mldsaL87, nil
	default:
		return 0, fmt.Errorf("expected 44|65|87; got %q", s)
	}
}

func genKEMPair(s kem.Scheme, outDir, role string, force bool) error {
	seedSize := s.SeedSize()
	seed := make([]byte, seedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return err
	}

	// CIRCL panics if seed length mismatches; keep it exact.
	pk, _ := s.DeriveKeyPair(seed)

	pub, err := pk.MarshalBinary()
	if err != nil {
		return err
	}

	seedPath := filepath.Join(outDir, fmt.Sprintf("%s.kem.seed", role))
	pubPath := filepath.Join(outDir, fmt.Sprintf("%s.kem.pub", role))
	if err := writeFileAtomic(seedPath, 0o600, seed, force); err != nil {
		return err
	}
	if err := writeFileAtomic(pubPath, 0o644, pub, force); err != nil {
		return err
	}

	// Optional convenience: hex digests (operators like having it)
	_ = writeFileAtomic(seedPath+".hex", 0o600, []byte(hex.EncodeToString(seed)+"\n"), force)
	_ = writeFileAtomic(pubPath+".hex", 0o644, []byte(hex.EncodeToString(pub)+"\n"), force)
	return nil
}

func genMLDSA44(outDir, role string, force bool) error {
	var seed [mldsa44.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return err
	}
	pk, sk := mldsa44.NewKeyFromSeed(&seed)

	pub := pk.Bytes()
	seedPath := filepath.Join(outDir, fmt.Sprintf("%s.sig.seed", role))
	pubPath := filepath.Join(outDir, fmt.Sprintf("%s.sig.pub", role))

	if err := writeFileAtomic(seedPath, 0o600, seed[:], force); err != nil {
		return err
	}
	if err := writeFileAtomic(pubPath, 0o644, pub, force); err != nil {
		return err
	}

	_ = sk // seed is the private handle; keep only seed on disk
	_ = writeFileAtomic(seedPath+".hex", 0o600, []byte(hex.EncodeToString(seed[:])+"\n"), force)
	_ = writeFileAtomic(pubPath+".hex", 0o644, []byte(hex.EncodeToString(pub)+"\n"), force)
	return nil
}

func genMLDSA65(outDir, role string, force bool) error {
	var seed [mldsa65.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return err
	}
	pk, sk := mldsa65.NewKeyFromSeed(&seed)

	pub := pk.Bytes()
	seedPath := filepath.Join(outDir, fmt.Sprintf("%s.sig.seed", role))
	pubPath := filepath.Join(outDir, fmt.Sprintf("%s.sig.pub", role))

	if err := writeFileAtomic(seedPath, 0o600, seed[:], force); err != nil {
		return err
	}
	if err := writeFileAtomic(pubPath, 0o644, pub, force); err != nil {
		return err
	}

	_ = sk
	_ = writeFileAtomic(seedPath+".hex", 0o600, []byte(hex.EncodeToString(seed[:])+"\n"), force)
	_ = writeFileAtomic(pubPath+".hex", 0o644, []byte(hex.EncodeToString(pub)+"\n"), force)
	return nil
}

func genMLDSA87(outDir, role string, force bool) error {
	var seed [mldsa87.SeedSize]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return err
	}
	pk, sk := mldsa87.NewKeyFromSeed(&seed)

	pub := pk.Bytes()
	seedPath := filepath.Join(outDir, fmt.Sprintf("%s.sig.seed", role))
	pubPath := filepath.Join(outDir, fmt.Sprintf("%s.sig.pub", role))

	if err := writeFileAtomic(seedPath, 0o600, seed[:], force); err != nil {
		return err
	}
	if err := writeFileAtomic(pubPath, 0o644, pub, force); err != nil {
		return err
	}

	_ = sk
	_ = writeFileAtomic(seedPath+".hex", 0o600, []byte(hex.EncodeToString(seed[:])+"\n"), force)
	_ = writeFileAtomic(pubPath+".hex", 0o644, []byte(hex.EncodeToString(pub)+"\n"), force)
	return nil
}

func writeFileAtomic(path string, mode os.FileMode, data []byte, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing file: %s (use -force)", path)
		}
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}
