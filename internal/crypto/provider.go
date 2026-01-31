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
	"context"
	"errors"
	"fmt"
)

type Mode uint8

const (
	ModeCircl   Mode = 1
	ModeOpenSSL Mode = 2
	ModeSystem  Mode = 3
)

func (m Mode) String() string {
	switch m {
	case ModeCircl:
		return "circl"
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
	case "application": // Legacy.
		return ModeCircl, nil
	case "circl":
		return ModeCircl, nil
	case "openssl":
		return ModeOpenSSL, nil
	case "system":
		return ModeSystem, nil
	default:
		return 0, fmt.Errorf("unknown mode: %q", s)
	}
}
