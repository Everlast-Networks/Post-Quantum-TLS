package crypto

import (
    "context"
    "errors"
    "fmt"
)

type Mode uint8

const (
    ModeApplication Mode = 1
    ModeOpenSSL     Mode = 2
    ModeSystem      Mode = 3
)

func (m Mode) String() string {
    switch m {
    case ModeApplication:
        return "application"
    case ModeOpenSSL:
        return "openssl"
    case ModeSystem:
        return "system"
    default:
        return fmt.Sprintf("mode(%d)", uint8(m))
    }
}

var (
    ErrUnsupported = errors.New("unsupported")
)

type Provider interface {
    Mode() Mode

    // KEM
    Encap(ctx context.Context, peerKEMPublic []byte) (kemCiphertext, sharedSecret []byte, err error)
    Decap(ctx context.Context, selfKEMPrivateOrSeed []byte, kemCiphertext []byte) (sharedSecret []byte, err error)

    // Signature
    Sign(ctx context.Context, selfSigPrivateOrSeed []byte, message []byte) (sig []byte, err error)
    Verify(ctx context.Context, peerSigPublic []byte, message []byte, sig []byte) error
}

func ModeFromString(s string) (Mode, error) {
    switch s {
    case "application":
        return ModeApplication, nil
    case "openssl":
        return ModeOpenSSL, nil
    case "system":
        return ModeSystem, nil
    default:
        return 0, fmt.Errorf("unknown mode: %q", s)
    }
}
