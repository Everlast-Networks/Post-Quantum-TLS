package bytesx

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

// DecodeFileBytes takes raw file content and returns a best-effort decode.
//
// Accepted formats:
//   - PEM; returns the first PEM block bytes
//   - hex (with or without 0x prefix; whitespace tolerated)
//   - base64 (standard or URL-safe; whitespace tolerated)
//   - raw bytes (fallback)
//
// Key point: it never trims raw binary; trimming only occurs for clearly text inputs.
// bytes.TrimSpace removes leading and trailing Unicode whitespace; that is unsafe for raw key bytes. :contentReference[oaicite:2]{index=2}
func DecodeFileBytes(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty input")
	}

	// PEM is unambiguously text; allow surrounding whitespace.
	tb := bytes.TrimSpace(b)
	if bytes.HasPrefix(tb, []byte("-----BEGIN")) {
		blk, _ := pem.Decode(tb)
		if blk == nil {
			return nil, errors.New("invalid PEM")
		}
		return blk.Bytes, nil
	}

	// If this does not look like ASCII text, treat it as raw binary; return unchanged.
	if !looksLikeASCIIText(b) {
		return b, nil
	}

	// Text path: normalise whitespace for hex/base64 decoding.
	s := strings.TrimSpace(string(b))
	if s == "" {
		return nil, errors.New("empty input")
	}
	s = strings.TrimPrefix(s, "0x")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, " ", "")

	// hex (strict)
	if len(s)%2 == 0 && isHex(s) {
		if out, err := hex.DecodeString(s); err == nil {
			return out, nil
		}
	}

	// base64 (standard)
	if out, err := base64.StdEncoding.DecodeString(s); err == nil {
		return out, nil
	}
	// base64 (url-safe, no padding)
	if out, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return out, nil
	}

	// Fallback for ASCII text that is neither PEM/hex/base64: return original bytes unchanged.
	// That preserves existing behaviour for odd key export formats.
	return b, nil
}

func looksLikeASCIIText(b []byte) bool {
	for _, c := range b {
		switch c {
		case '\r', '\n', '\t', ' ':
			continue
		default:
			// printable ASCII range only
			if c < 0x20 || c > 0x7E {
				return false
			}
		}
	}
	return true
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
