package crypto

import (
    "crypto/rand"
    "errors"

    "golang.org/x/crypto/chacha20poly1305"
)

const NonceSize = chacha20poly1305.NonceSizeX // 24

func NewNonce() ([]byte, error) {
    n := make([]byte, NonceSize)
    if _, err := rand.Read(n); err != nil {
        return nil, err
    }
    return n, nil
}

func Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
    if len(key) != chacha20poly1305.KeySize {
        return nil, errors.New("bad key size")
    }
    if len(nonce) != NonceSize {
        return nil, errors.New("bad nonce size")
    }
    a, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }
    return a.Seal(nil, nonce, plaintext, aad), nil
}

func Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
    if len(key) != chacha20poly1305.KeySize {
        return nil, errors.New("bad key size")
    }
    if len(nonce) != NonceSize {
        return nil, errors.New("bad nonce size")
    }
    a, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }
    return a.Open(nil, nonce, ciphertext, aad)
}
