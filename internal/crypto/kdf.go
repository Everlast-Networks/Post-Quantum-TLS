package crypto

import (
    "crypto/sha256"

    "golang.org/x/crypto/hkdf"
)

func HKDF32(sharedSecret, salt, info []byte) ([]byte, error) {
    r := hkdf.New(sha256.New, sharedSecret, salt, info)
    out := make([]byte, 32)
    if _, err := r.Read(out); err != nil {
        return nil, err
    }
    return out, nil
}
