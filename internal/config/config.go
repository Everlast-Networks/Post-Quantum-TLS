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
	ModeApplication Mode = "application"
	ModeOpenSSL     Mode = "openssl"
	ModeSystem      Mode = "system" // Windows only
)

type OpenSSLConfig struct {
	Dir string `yaml:"dir"`
	// If set, overrides Dir on Windows when calling as a system command.
	Command string `yaml:"command"`
}

type KeyConfig struct {
	// ML-KEM-1024
	KEMPublicPath  string `yaml:"kem_public_path"`
	KEMPrivatePath string `yaml:"kem_private_path"`
	KEMSeedPath    string `yaml:"kem_seed_path"`

	// ML-DSA
	SigPublicPath  string `yaml:"sig_public_path"`
	SigPrivatePath string `yaml:"sig_private_path"`
	SigSeedPath    string `yaml:"sig_seed_path"`
}

type ClientConfig struct {
	Mode             Mode          `yaml:"mode"`
	CertsDir         string        `yaml:"certs_dir"`
	OpenSSL          OpenSSLConfig `yaml:"openssl"`
	Keys             KeyConfig     `yaml:"keys"`
	ReplayTTLSeconds int           `yaml:"replay_ttl_seconds"`
}

type ServerConfig struct {
	Mode             Mode          `yaml:"mode"`
	CertsDir         string        `yaml:"certs_dir"`
	OpenSSL          OpenSSLConfig `yaml:"openssl"`
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
	c.Keys = withCertsDir(c.CertsDir, c.Keys)

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
	c.Keys = withCertsDir(c.CertsDir, c.Keys)

	if err := c.validate(); err != nil {
		return ServerConfig{}, err
	}
	return c, nil
}

func (c *ClientConfig) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeApplication
	}
	if c.CertsDir == "" {
		c.CertsDir = "./certs"
	}
	if c.ReplayTTLSeconds == 0 {
		c.ReplayTTLSeconds = 120
	}
	c.Keys = withCertsDir(c.CertsDir, c.Keys)
}

func (c *ServerConfig) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeApplication
	}
	if c.CertsDir == "" {
		c.CertsDir = "./certs"
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
	c.Keys = withCertsDir(c.CertsDir, c.Keys)
}

func (c ClientConfig) validate() error {
	switch c.Mode {
	case ModeApplication:
	case ModeOpenSSL:
	case ModeSystem:
		if runtime.GOOS != "windows" {
			return errors.New("mode=system is supported on Windows only")
		}
	default:
		return errors.New("invalid mode; use application|openssl|system")
	}
	return nil
}

func (c ServerConfig) validate() error {
	switch c.Mode {
	case ModeApplication:
	case ModeOpenSSL:
	default:
		return errors.New("invalid mode; use application|openssl")
	}
	if c.Listen == "" || c.Upstream == "" {
		return errors.New("listen and upstream are required")
	}
	return nil
}

func withCertsDir(certsDir string, k KeyConfig) KeyConfig {
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

func ResolveOpenSSLCommand(dir, override string) string {
	if override != "" {
		return override
	}
	if dir == "" {
		return "openssl"
	}
	exe := "openssl"
	if runtime.GOOS == "windows" {
		exe = "openssl.exe"
	}
	return filepath.Join(dir, "bin", exe)
}
