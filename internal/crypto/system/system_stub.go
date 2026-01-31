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
