package openssl

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	qcrypto "github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/version"
)

type Provider struct {
	cmd string
}

func New(opensslCmd string) *Provider {
	if opensslCmd == "" {
		opensslCmd = "openssl"
	}
	return &Provider{cmd: opensslCmd}
}

func (p *Provider) Mode() qcrypto.Mode { return qcrypto.ModeOpenSSL }

func looksLikePEM(b []byte) bool {
	b = bytes.TrimSpace(b)
	return bytes.HasPrefix(b, []byte("-----BEGIN "))
}

func keyformArgs(keyBytes []byte) []string {
	if looksLikePEM(keyBytes) {
		return nil
	}
	// OpenSSL pkeyutl defaults to PEM; DER inputs must be explicit.
	return []string{"-keyform", "DER"}
}

func (p *Provider) Encap(ctx context.Context, peerKEMPublic []byte) ([]byte, []byte, error) {
	dir, err := os.MkdirTemp("", "qtls-ossl-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(dir)

	pubPath := filepath.Join(dir, "peer_kem_pub.key")
	if err := os.WriteFile(pubPath, peerKEMPublic, 0o600); err != nil {
		return nil, nil, err
	}
	ctPath := filepath.Join(dir, "kem.ct")
	ssPath := filepath.Join(dir, "kem.ss")

	// openssl pkeyutl -encap -inkey <pub> [-keyform DER] -pubin -out <ct> -secret <ss>
	args := []string{"pkeyutl", "-encap", "-inkey", pubPath}
	args = append(args, keyformArgs(peerKEMPublic)...)
	args = append(args, "-pubin", "-out", ctPath, "-secret", ssPath)

	if _, _, err := p.run(ctx, args, nil); err != nil {
		return nil, nil, fmt.Errorf("openssl kem encap failed: %w", err)
	}

	ct, err := os.ReadFile(ctPath)
	if err != nil {
		return nil, nil, err
	}
	ss, err := os.ReadFile(ssPath)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (p *Provider) Decap(ctx context.Context, selfKEMPrivate []byte, kemCiphertext []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "qtls-ossl-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	privPath := filepath.Join(dir, "self_kem_priv.key")
	if err := os.WriteFile(privPath, selfKEMPrivate, 0o600); err != nil {
		return nil, err
	}
	ctPath := filepath.Join(dir, "kem.ct")
	if err := os.WriteFile(ctPath, kemCiphertext, 0o600); err != nil {
		return nil, err
	}
	ssPath := filepath.Join(dir, "kem.ss")

	// openssl pkeyutl -decap -inkey <priv> [-keyform DER] -in <ct> -secret <ss>
	args := []string{"pkeyutl", "-decap", "-inkey", privPath}
	args = append(args, keyformArgs(selfKEMPrivate)...)
	args = append(args, "-in", ctPath, "-secret", ssPath)

	if _, _, err := p.run(ctx, args, nil); err != nil {
		return nil, fmt.Errorf("openssl kem decap failed: %w", err)
	}

	ss, err := os.ReadFile(ssPath)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (p *Provider) Sign(ctx context.Context, selfSigPrivate []byte, message []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "qtls-ossl-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	privPath := filepath.Join(dir, "self_sig_priv.key")
	if err := os.WriteFile(privPath, selfSigPrivate, 0o600); err != nil {
		return nil, err
	}
	inPath := filepath.Join(dir, "msg.bin")
	if err := os.WriteFile(inPath, message, 0o600); err != nil {
		return nil, err
	}
	sigPath := filepath.Join(dir, "sig.bin")

	// openssl pkeyutl -sign -in <msg> -inkey <priv> [-keyform DER] -out <sig> -pkeyopt context-string:<ctx>
	args := []string{"pkeyutl", "-sign", "-in", inPath, "-inkey", privPath}
	args = append(args, keyformArgs(selfSigPrivate)...)
	args = append(args, "-out", sigPath, "-pkeyopt", "context-string:"+version.SigContext)

	if _, _, err := p.run(ctx, args, nil); err != nil {
		return nil, fmt.Errorf("openssl sign failed: %w", err)
	}

	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func (p *Provider) Verify(ctx context.Context, peerSigPublic []byte, message []byte, sig []byte) error {
	dir, err := os.MkdirTemp("", "qtls-ossl-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	pubPath := filepath.Join(dir, "peer_sig_pub.key")
	if err := os.WriteFile(pubPath, peerSigPublic, 0o600); err != nil {
		return err
	}
	inPath := filepath.Join(dir, "msg.bin")
	if err := os.WriteFile(inPath, message, 0o600); err != nil {
		return err
	}
	sigPath := filepath.Join(dir, "sig.bin")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		return err
	}

	// openssl pkeyutl -verify -in <msg> -inkey <pub> [-keyform DER] -pubin -sigfile <sig> -pkeyopt context-string:<ctx>
	args := []string{"pkeyutl", "-verify", "-in", inPath, "-inkey", pubPath}
	args = append(args, keyformArgs(peerSigPublic)...)
	args = append(args, "-pubin", "-sigfile", sigPath, "-pkeyopt", "context-string:"+version.SigContext)

	if _, _, err := p.run(ctx, args, nil); err != nil {
		return fmt.Errorf("openssl verify failed: %w", err)
	}
	return nil
}

func (p *Provider) run(ctx context.Context, args []string, stdin []byte) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, p.cmd, args...)

	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	if err := cmd.Run(); err != nil {
		full := strings.Join(append([]string{p.cmd}, args...), " ")
		return outb.Bytes(), errb.Bytes(), fmt.Errorf("openssl failed: %w; cmd=%q; stderr=%q", err, full, errb.String())
	}
	return outb.Bytes(), errb.Bytes(), nil
}
