//go:build !windows

package system

import (
    "context"

    qcrypto "github.com/example/qtls/internal/crypto"
)

type Provider struct{}

func New() *Provider { return &Provider{} }

func (p *Provider) Mode() qcrypto.Mode { return qcrypto.ModeSystem }

func (p *Provider) Encap(ctx context.Context, peerKEMPublic []byte) ([]byte, []byte, error) {
    return nil, nil, qcrypto.ErrUnsupported
}

func (p *Provider) Decap(ctx context.Context, selfKEMPrivateOrSeed []byte, kemCiphertext []byte) ([]byte, error) {
    return nil, qcrypto.ErrUnsupported
}

func (p *Provider) Sign(ctx context.Context, selfSigPrivateOrSeed []byte, message []byte) ([]byte, error) {
    return nil, qcrypto.ErrUnsupported
}

func (p *Provider) Verify(ctx context.Context, peerSigPublic []byte, message []byte, sig []byte) error {
    return qcrypto.ErrUnsupported
}

// Supported reports whether CNG PQC is available.
func Supported() (bool, string) {
    return false, "system mode is supported on Windows only"
}
