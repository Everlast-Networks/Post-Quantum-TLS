package payload

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// RequestPayload and ResponsePayload are encrypted (AEAD) inside the envelope.
type RequestPayload struct {
	Headers map[string]string
	Body    []byte
}

type ResponsePayload struct {
	Headers map[string]string
	Body    []byte
}

func (p RequestPayload) MarshalBinary() ([]byte, error) {
	return marshalKVAndBody(p.Headers, p.Body), nil
}

func (p *RequestPayload) UnmarshalBinary(b []byte) error {
	hdrs, body, err := unmarshalKVAndBody(b)
	if err != nil {
		return err
	}
	p.Headers = hdrs
	p.Body = body
	return nil
}

func (p ResponsePayload) MarshalBinary() ([]byte, error) {
	return marshalKVAndBody(p.Headers, p.Body), nil
}

func (p *ResponsePayload) UnmarshalBinary(b []byte) error {
	hdrs, body, err := unmarshalKVAndBody(b)
	if err != nil {
		return err
	}
	p.Headers = hdrs
	p.Body = body
	return nil
}

func marshalKVAndBody(h map[string]string, body []byte) []byte {
	var buf bytes.Buffer

	// Preserve keys exactly as provided; internal control headers rely on exact spelling.
	// Determinism is provided by sorting keys.
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sortStrings(keys)

	_ = binary.Write(&buf, binary.BigEndian, uint32(len(keys)))
	for _, k := range keys {
		v := h[k]
		writeString(&buf, k)
		writeString(&buf, v)
	}
	writeBytes(&buf, body)
	return buf.Bytes()
}

func unmarshalKVAndBody(b []byte) (map[string]string, []byte, error) {
	r := bytes.NewReader(b)
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, nil, err
	}
	hdrs := make(map[string]string, n)
	for i := uint32(0); i < n; i++ {
		k, err := readString(r)
		if err != nil {
			return nil, nil, err
		}
		v, err := readString(r)
		if err != nil {
			return nil, nil, err
		}
		hdrs[k] = v
	}
	body, err := readBytes(r)
	if err != nil {
		return nil, nil, err
	}
	if r.Len() != 0 {
		return nil, nil, errors.New("trailing payload bytes")
	}
	return hdrs, body, nil
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
	for i := 0; i < len(a); i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				a[i], a[j] = a[j], a[i]
			}
		}
	}
}
