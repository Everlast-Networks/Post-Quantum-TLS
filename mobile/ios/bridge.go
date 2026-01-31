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

package qtlsbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/crypto/app"
	"github.com/example/qtls/internal/envelope"
	"github.com/example/qtls/internal/qtls"
)

// BridgeConfig is passed as JSON for mobile callers; it avoids exposing file paths.
//
// All fields are base64-encoded raw bytes as used by circl mode.
// For V1 iOS usage, keep this in the keychain or app-managed encrypted storage.
type BridgeConfig struct {
	SelfKEMPrivateOrSeed string `json:"self_kem_private_or_seed_b64"`
	SelfSigPrivateOrSeed string `json:"self_sig_private_or_seed_b64"`
	PeerKEMPublic        string `json:"peer_kem_public_b64"`
	PeerSigPublic        string `json:"peer_sig_public_b64"`
}

// SealRequest produces an opaque binary envelope.
func SealRequest(cfgJSON string, method string, path string, headersJSON string, body []byte) ([]byte, error) {
	cfg, keys, err := parse(cfgJSON)
	_ = cfg
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	if headersJSON != "" {
		if err := json.Unmarshal([]byte(headersJSON), &headers); err != nil {
			return nil, err
		}
	}

	prov, err := app.New()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	msg, err := qtls.SealRequest(ctx, qtls.Options{Provider: prov}, keys, crypto.ModeCircl, method, path, headers, body)
	if err != nil {
		return nil, err
	}
	return msg.MarshalBinary()
}

// OpenResponse validates and decrypts a response envelope.
func OpenResponse(cfgJSON string, envelopeBytes []byte) (status int, headersJSON string, body []byte, err error) {
	_, keys, err := parse(cfgJSON)
	if err != nil {
		return 0, "", nil, err
	}

	prov, err := app.New()
	if err != nil {
		return 0, "", nil, err
	}

	var msg envelope.Message
	if err := msg.UnmarshalBinary(envelopeBytes); err != nil {
		return 0, "", nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pl, err := qtls.OpenResponse(ctx, qtls.Options{Provider: prov}, keys, msg)
	if err != nil {
		return 0, "", nil, err
	}

	hb, _ := json.Marshal(pl.Headers)
	return int(msg.Header.StatusCode), string(hb), pl.Body, nil
}

func parse(cfgJSON string) (BridgeConfig, qtls.Keys, error) {
	if cfgJSON == "" {
		return BridgeConfig{}, qtls.Keys{}, errors.New("cfgJSON is required")
	}
	var cfg BridgeConfig
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return BridgeConfig{}, qtls.Keys{}, err
	}
	dec := func(s string) ([]byte, error) {
		if s == "" {
			return nil, errors.New("missing base64 field")
		}
		return base64.StdEncoding.DecodeString(s)
	}

	kemPriv, err := dec(cfg.SelfKEMPrivateOrSeed)
	if err != nil {
		return BridgeConfig{}, qtls.Keys{}, err
	}
	sigPriv, err := dec(cfg.SelfSigPrivateOrSeed)
	if err != nil {
		return BridgeConfig{}, qtls.Keys{}, err
	}
	peerKem, err := dec(cfg.PeerKEMPublic)
	if err != nil {
		return BridgeConfig{}, qtls.Keys{}, err
	}
	peerSig, err := dec(cfg.PeerSigPublic)
	if err != nil {
		return BridgeConfig{}, qtls.Keys{}, err
	}

	return cfg, qtls.Keys{
		KEMPrivateOrSeed: kemPriv,
		SigPrivateOrSeed: sigPriv,
		PeerKEMPublic:    peerKem,
		PeerSigPublic:    peerSig,
	}, nil
}
