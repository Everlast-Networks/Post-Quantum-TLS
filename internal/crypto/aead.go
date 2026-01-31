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
