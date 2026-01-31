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

package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/example/qtls/internal/version"
)

type Kind uint8

const (
	KindRequest  Kind = 1
	KindResponse Kind = 2
)

// Header is authenticated (AEAD additional data) and signed.
type Header struct {
	Magic   [4]byte
	Version uint16
	Kind    Kind

	Mode uint8 // 1=circl, 2=openssl, 3=system (Windows)
	// V1: ML-KEM-1024 fixed.
	// Signature scheme is inferred from the public key material in use.
	TimestampUnixMilli int64

	ReplayID [16]byte

	Method string
	Path   string

	// Request headers; stored as an explicit set.
	Headers map[string]string

	// For responses.
	StatusCode uint16
}

type Message struct {
	Header Header

	// KEM ciphertext; used to derive the shared secret.
	KEMCiphertext []byte

	// AEAD nonce for payload encryption.
	Nonce []byte

	// Ciphertext of payload; payload is a protobuf-free framing of headers/body for portability.
	PayloadCiphertext []byte

	// Signature over (header_bytes || kem_ciphertext || nonce || payload_ciphertext)
	Signature []byte
}

func NewHeader(kind Kind) Header {
	var h Header
	copy(h.Magic[:], []byte(version.ProtocolMagic))
	h.Version = version.ProtocolVersion
	h.Kind = kind
	h.TimestampUnixMilli = time.Now().UTC().UnixMilli()
	h.Headers = make(map[string]string)
	return h
}

func (h Header) MarshalBinary() ([]byte, error) {
	// Deterministic encoding.
	var buf bytes.Buffer
	buf.Write(h.Magic[:])
	_ = binary.Write(&buf, binary.BigEndian, h.Version)
	buf.WriteByte(byte(h.Kind))
	buf.WriteByte(h.Mode)
	_ = binary.Write(&buf, binary.BigEndian, h.TimestampUnixMilli)
	buf.Write(h.ReplayID[:])

	writeString(&buf, h.Method)
	writeString(&buf, h.Path)

	// Preserve keys exactly as provided; determinism comes from sorting.
	keys := make([]string, 0, len(h.Headers))
	for k := range h.Headers {
		keys = append(keys, k)
	}
	sortStrings(keys)

	_ = binary.Write(&buf, binary.BigEndian, uint32(len(keys)))
	for _, k := range keys {
		v := h.Headers[k]
		writeString(&buf, k)
		writeString(&buf, v)
	}

	_ = binary.Write(&buf, binary.BigEndian, h.StatusCode)
	return buf.Bytes(), nil
}

func (h *Header) UnmarshalBinary(b []byte) error {
	r := bytes.NewReader(b)
	if _, err := io.ReadFull(r, h.Magic[:]); err != nil {
		return err
	}
	if string(h.Magic[:]) != version.ProtocolMagic {
		return errors.New("bad magic")
	}
	if err := binary.Read(r, binary.BigEndian, &h.Version); err != nil {
		return err
	}
	if h.Version != version.ProtocolVersion {
		return errors.New("unsupported protocol version")
	}
	k, err := r.ReadByte()
	if err != nil {
		return err
	}
	h.Kind = Kind(k)
	m, err := r.ReadByte()
	if err != nil {
		return err
	}
	h.Mode = m
	if err := binary.Read(r, binary.BigEndian, &h.TimestampUnixMilli); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.ReplayID[:]); err != nil {
		return err
	}

	if h.Method, err = readString(r); err != nil {
		return err
	}
	if h.Path, err = readString(r); err != nil {
		return err
	}

	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return err
	}
	h.Headers = make(map[string]string, n)
	for i := uint32(0); i < n; i++ {
		k, err := readString(r)
		if err != nil {
			return err
		}
		v, err := readString(r)
		if err != nil {
			return err
		}
		h.Headers[k] = v
	}

	if err := binary.Read(r, binary.BigEndian, &h.StatusCode); err != nil {
		return err
	}

	if r.Len() != 0 {
		return errors.New("trailing header bytes")
	}
	return nil
}

func (m Message) MarshalBinary() ([]byte, error) {
	hb, err := m.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	writeBytes(&buf, hb)
	writeBytes(&buf, m.KEMCiphertext)
	writeBytes(&buf, m.Nonce)
	writeBytes(&buf, m.PayloadCiphertext)
	writeBytes(&buf, m.Signature)
	return buf.Bytes(), nil
}

func (m *Message) UnmarshalBinary(b []byte) error {
	r := bytes.NewReader(b)
	hb, err := readBytes(r)
	if err != nil {
		return err
	}
	if err := m.Header.UnmarshalBinary(hb); err != nil {
		return err
	}
	if m.KEMCiphertext, err = readBytes(r); err != nil {
		return err
	}
	if m.Nonce, err = readBytes(r); err != nil {
		return err
	}
	if m.PayloadCiphertext, err = readBytes(r); err != nil {
		return err
	}
	if m.Signature, err = readBytes(r); err != nil {
		return err
	}
	if r.Len() != 0 {
		return errors.New("trailing message bytes")
	}
	return nil
}

func SignedBytes(hb []byte, kemct, nonce, payloadct []byte) []byte {
	var buf bytes.Buffer
	writeBytes(&buf, hb)
	writeBytes(&buf, kemct)
	writeBytes(&buf, nonce)
	writeBytes(&buf, payloadct)
	return buf.Bytes()
}

func writeString(w io.Writer, s string) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(s)))
	_, _ = w.Write([]byte(s))
}

func readString(r io.Reader) (string, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", err
	}
	return string(b), nil
}

func writeBytes(w io.Writer, b []byte) {
	_ = binary.Write(w, binary.BigEndian, uint32(len(b)))
	_, _ = w.Write(b)
}

func readBytes(r io.Reader) ([]byte, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func sortStrings(a []string) {
	// Small deterministic sort; avoids bringing in extra deps.
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}
