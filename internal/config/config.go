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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeCircl       Mode = "circl"
	ModeApplication Mode = "application" // Legacy
	ModeOpenSSL     Mode = "openssl"
	ModeSystem      Mode = "system" // Windows only
)

type OpenSSLConfig struct {
	// Dir points to a standalone OpenSSL install (expected layout: <dir>/bin/openssl).
	// On Windows, default behaviour is to call openssl.exe via PATH; set Command to override.
	Dir string `yaml:"dir"`

	// Command overrides Dir; useful on Windows to pin a specific openssl.exe.
	Command string `yaml:"command"`

	// ConfPath, if set, is exported to OPENSSL_CONF for this process.
	// Useful for provider config in R&D environments.
	ConfPath string `yaml:"conf_path"`
}

type X509Config struct {
	// Filenames may be absolute or relative to certs_dir.
	RootCertPath   string `yaml:"root_cert_path"`   // root.crt
	ChainCertPath  string `yaml:"chain_path"`       // chain.pem (optional)
	ClientCertPath string `yaml:"client_cert_path"` // client.crt
	ServerCertPath string `yaml:"server_cert_path"` // server.crt
}

type KeyConfig struct {
	// ML-KEM-1024 (QTLS payload KEM; keep sidecar files for normal operation)
	KEMPublicPath  string `yaml:"kem_public_path"`
	KEMPrivatePath string `yaml:"kem_private_path"`
	KEMSeedPath    string `yaml:"kem_seed_path"`

	// ML-DSA (QTLS message signatures)
	SigPublicPath  string `yaml:"sig_public_path"`
	SigPrivatePath string `yaml:"sig_private_path"`
	SigSeedPath    string `yaml:"sig_seed_path"`
}

type ClientConfig struct {
	Mode             Mode          `yaml:"mode"`
	CertsDir         string        `yaml:"certs_dir"`
	OpenSSL          OpenSSLConfig `yaml:"openssl"`
	X509             X509Config    `yaml:"x509"`
	Keys             KeyConfig     `yaml:"keys"`
	ReplayTTLSeconds int           `yaml:"replay_ttl_seconds"`
}

type ServerConfig struct {
	Mode             Mode          `yaml:"mode"`
	CertsDir         string        `yaml:"certs_dir"`
	OpenSSL          OpenSSLConfig `yaml:"openssl"`
	X509             X509Config    `yaml:"x509"`
	Keys             KeyConfig     `yaml:"keys"`
	Listen           string        `yaml:"listen"`
	Upstream         string        `yaml:"upstream"`
	ReplayTTLSeconds int           `yaml:"replay_ttl_seconds"`
	ReplayMaxEntries int           `yaml:"replay_max_entries"`
}

func LoadClient(path string) (ClientConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ClientConfig{}, err
	}
	var c ClientConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return ClientConfig{}, err
	}

	c.applyDefaults()

	// Resolve certs_dir relative to the YAML location; not the working directory.
	baseDir := filepath.Dir(path)
	if c.CertsDir == "" {
		c.CertsDir = "./certs"
	}
	if !filepath.IsAbs(c.CertsDir) {
		c.CertsDir = filepath.Clean(filepath.Join(baseDir, c.CertsDir))
	}

	c.X509 = withCertsDirX509(c.CertsDir, c.X509)
	c.Keys = withCertsDirKeys(c.CertsDir, c.Keys)
	c.OpenSSL = withCertsDirOpenSSL(c.CertsDir, c.OpenSSL)

	if err := c.validate(); err != nil {
		return ClientConfig{}, err
	}
	return c, nil
}

func LoadServer(path string) (ServerConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return ServerConfig{}, err
	}
	var c ServerConfig
	if err := yaml.Unmarshal(b, &c); err != nil {
		return ServerConfig{}, err
	}

	c.applyDefaults()

	baseDir := filepath.Dir(path)
	if c.CertsDir == "" {
		c.CertsDir = "./certs"
	}
	if !filepath.IsAbs(c.CertsDir) {
		c.CertsDir = filepath.Clean(filepath.Join(baseDir, c.CertsDir))
	}

	c.X509 = withCertsDirX509(c.CertsDir, c.X509)
	c.Keys = withCertsDirKeys(c.CertsDir, c.Keys)
	c.OpenSSL = withCertsDirOpenSSL(c.CertsDir, c.OpenSSL)

	if err := c.validate(); err != nil {
		return ServerConfig{}, err
	}
	return c, nil
}

func (c *ClientConfig) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeApplication
	}
	if c.ReplayTTLSeconds == 0 {
		c.ReplayTTLSeconds = 120
	}
	c.X509 = withDefaultsX509(c.X509)
	c.OpenSSL = withDefaultsOpenSSL(c.OpenSSL, runtime.GOOS)
}

func (c *ServerConfig) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeApplication
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:5000"
	}
	if c.Upstream == "" {
		c.Upstream = "http://127.0.0.1:5500"
	}
	if c.ReplayTTLSeconds == 0 {
		c.ReplayTTLSeconds = 120
	}
	if c.ReplayMaxEntries == 0 {
		c.ReplayMaxEntries = 200000
	}
	c.X509 = withDefaultsX509(c.X509)
	c.OpenSSL = withDefaultsOpenSSL(c.OpenSSL, runtime.GOOS)
}

func withDefaultsX509(x X509Config) X509Config {
	if x.RootCertPath == "" {
		x.RootCertPath = "root.crt"
	}
	if x.ChainCertPath == "" {
		x.ChainCertPath = "chain.pem"
	}
	if x.ClientCertPath == "" {
		x.ClientCertPath = "client.crt"
	}
	if x.ServerCertPath == "" {
		x.ServerCertPath = "server.crt"
	}
	return x
}

func withDefaultsOpenSSL(o OpenSSLConfig, goos string) OpenSSLConfig {
	if o.ConfPath == "" {
		o.ConfPath = "openssl/openssl.cnf"
	}
	if goos != "windows" && o.Dir == "" {
		o.Dir = "/opt/ossl-3.5"
	}
	return o
}

func (c ClientConfig) validate() error {
	switch c.Mode {
	case ModeCircl, ModeApplication:
	case ModeOpenSSL:
	case ModeSystem:
		if runtime.GOOS != "windows" {
			return errors.New("mode=system is supported on Windows only")
		}
	default:
		return errors.New("invalid mode; use circl|openssl|system")
	}
	return nil
}

func (c ServerConfig) validate() error {
	switch c.Mode {
	case ModeCircl, ModeApplication:
	case ModeOpenSSL:
	default:
		return errors.New("invalid mode; use circl|openssl")
	}
	if c.Listen == "" || c.Upstream == "" {
		return errors.New("listen and upstream are required")
	}
	return nil
}

func withCertsDirX509(certsDir string, x X509Config) X509Config {
	joinIfRel := func(p string) string {
		if p == "" {
			return ""
		}
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(certsDir, p)
	}
	x.RootCertPath = joinIfRel(x.RootCertPath)
	x.ChainCertPath = joinIfRel(x.ChainCertPath)
	x.ClientCertPath = joinIfRel(x.ClientCertPath)
	x.ServerCertPath = joinIfRel(x.ServerCertPath)
	return x
}

func withCertsDirKeys(certsDir string, k KeyConfig) KeyConfig {
	joinIfRel := func(p string) string {
		if p == "" {
			return ""
		}
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(certsDir, p)
	}
	k.KEMPublicPath = joinIfRel(k.KEMPublicPath)
	k.KEMPrivatePath = joinIfRel(k.KEMPrivatePath)
	k.KEMSeedPath = joinIfRel(k.KEMSeedPath)
	k.SigPublicPath = joinIfRel(k.SigPublicPath)
	k.SigPrivatePath = joinIfRel(k.SigPrivatePath)
	k.SigSeedPath = joinIfRel(k.SigSeedPath)
	return k
}

func withCertsDirOpenSSL(certsDir string, o OpenSSLConfig) OpenSSLConfig {
	if o.ConfPath == "" {
		return o
	}
	if filepath.IsAbs(o.ConfPath) {
		return o
	}
	o.ConfPath = filepath.Join(certsDir, o.ConfPath)
	return o
}

func ResolveOpenSSLCommand(dir, override string) string {
	if override != "" {
		return override
	}
	if runtime.GOOS == "windows" {
		return "openssl.exe"
	}
	if dir == "" {
		return "openssl"
	}
	return filepath.Join(dir, "bin", "openssl")
}
