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

package keyimport

import (
	"encoding/asn1"
	"errors"
)

// UnwrapPublic unwraps SubjectPublicKeyInfo (SPKI) and returns subjectPublicKey bytes.
// If b is not SPKI, it returns b unchanged.
func UnwrapPublic(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty public key")
	}

	type algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
		Params    asn1.RawValue `asn1:"optional"`
	}
	type spki struct {
		Algorithm        algorithmIdentifier
		SubjectPublicKey asn1.BitString
	}

	var s spki
	rest, err := asn1.Unmarshal(b, &s)
	if err != nil || len(rest) != 0 || len(s.SubjectPublicKey.Bytes) == 0 {
		return b, nil
	}
	return s.SubjectPublicKey.Bytes, nil
}

// UnwrapPrivate unwraps PKCS#8 PrivateKeyInfo and returns the inner privateKey OCTET STRING bytes.
// If b is not PKCS#8, it returns b unchanged.
func UnwrapPrivate(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty private key")
	}

	type algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
		Params    asn1.RawValue `asn1:"optional"`
	}
	type pkcs8 struct {
		Version    int
		Algorithm  algorithmIdentifier
		PrivateKey []byte
	}

	var p pkcs8
	rest, err := asn1.Unmarshal(b, &p)
	if err != nil || len(rest) != 0 || len(p.PrivateKey) == 0 {
		return b, nil
	}
	return p.PrivateKey, nil
}
