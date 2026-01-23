package qtls

import (
    "context"
    "crypto/rand"
    "encoding/binary"
    "errors"
    "fmt"
    "io"
    "os"
    "time"

    "github.com/example/qtls/internal/bytesx"
    "github.com/example/qtls/internal/crypto"
    "github.com/example/qtls/internal/envelope"
    "github.com/example/qtls/internal/payload"
    "github.com/example/qtls/internal/version"
)

type Keys struct {
    // Local keys.
    KEMPrivateOrSeed []byte
    SigPrivateOrSeed []byte

    // Peer keys.
    PeerKEMPublic []byte
    PeerSigPublic []byte
}

type Options struct {
    Provider crypto.Provider

    // Optional salt for HKDF; keep stable for a deployment.
    KDFSalt []byte
}

func DecodeKeyBytesForMode(mode crypto.Mode, b []byte) ([]byte, error) {
    if mode == crypto.ModeOpenSSL {
        return b, nil
    }
    return bytesx.DecodeFileBytes(b)
}

func LoadKeyFile(path string) ([]byte, error) {
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    return bytesx.DecodeFileBytes(b)
}

func SealRequest(ctx context.Context, opts Options, keys Keys, mode crypto.Mode, method, path string, hdrs map[string]string, body []byte) (envelope.Message, error) {
    if opts.Provider == nil {
        return envelope.Message{}, errors.New("provider is required")
    }

    h := envelope.NewHeader(envelope.KindRequest)
    h.Mode = uint8(mode)
    h.Method = method
    h.Path = path
    h.Headers = cloneMap(hdrs)

    if _, err := io.ReadFull(rand.Reader, h.ReplayID[:]); err != nil {
        return envelope.Message{}, err
    }

    hb, err := h.MarshalBinary()
    if err != nil {
        return envelope.Message{}, err
    }

    kemCT, ss, err := opts.Provider.Encap(ctx, keys.PeerKEMPublic)
    if err != nil {
        return envelope.Message{}, err
    }

    nonce, err := crypto.NewNonce()
    if err != nil {
        return envelope.Message{}, err
    }

    kdfInfo := kdfInfo(h.ReplayID, envelope.KindRequest)
    aeadKey, err := crypto.HKDF32(ss, opts.KDFSalt, kdfInfo)
    if err != nil {
        return envelope.Message{}, err
    }

    pl := payload.RequestPayload{Headers: hdrs, Body: body}
    plb, err := pl.MarshalBinary()
    if err != nil {
        return envelope.Message{}, err
    }
    aad := hb
    plct, err := crypto.Seal(aeadKey, nonce, aad, plb)
    if err != nil {
        return envelope.Message{}, err
    }

    signed := envelope.SignedBytes(hb, kemCT, nonce, plct)
    sig, err := opts.Provider.Sign(ctx, keys.SigPrivateOrSeed, signed)
    if err != nil {
        return envelope.Message{}, err
    }

    return envelope.Message{
        Header:            h,
        KEMCiphertext:     kemCT,
        Nonce:             nonce,
        PayloadCiphertext: plct,
        Signature:         sig,
    }, nil
}

func OpenRequest(ctx context.Context, opts Options, keys Keys, msg envelope.Message) (payload.RequestPayload, error) {
    if opts.Provider == nil {
        return payload.RequestPayload{}, errors.New("provider is required")
    }

    hb, err := msg.Header.MarshalBinary()
    if err != nil {
        return payload.RequestPayload{}, err
    }

    signed := envelope.SignedBytes(hb, msg.KEMCiphertext, msg.Nonce, msg.PayloadCiphertext)
    if err := opts.Provider.Verify(ctx, keys.PeerSigPublic, signed, msg.Signature); err != nil {
        return payload.RequestPayload{}, err
    }

    ss, err := opts.Provider.Decap(ctx, keys.KEMPrivateOrSeed, msg.KEMCiphertext)
    if err != nil {
        return payload.RequestPayload{}, err
    }

    kdfInfo := kdfInfo(msg.Header.ReplayID, envelope.KindRequest)
    aeadKey, err := crypto.HKDF32(ss, opts.KDFSalt, kdfInfo)
    if err != nil {
        return payload.RequestPayload{}, err
    }

    plb, err := crypto.Open(aeadKey, msg.Nonce, hb, msg.PayloadCiphertext)
    if err != nil {
        return payload.RequestPayload{}, err
    }

    var pl payload.RequestPayload
    if err := pl.UnmarshalBinary(plb); err != nil {
        return payload.RequestPayload{}, err
    }
    return pl, nil
}

func SealResponse(ctx context.Context, opts Options, keys Keys, mode crypto.Mode, statusCode int, hdrs map[string]string, body []byte, replayID [16]byte) (envelope.Message, error) {
    if opts.Provider == nil {
        return envelope.Message{}, errors.New("provider is required")
    }

    h := envelope.NewHeader(envelope.KindResponse)
    h.Mode = uint8(mode)
    h.ReplayID = replayID
    h.StatusCode = uint16(statusCode)
    h.Headers = cloneMap(hdrs)

    hb, err := h.MarshalBinary()
    if err != nil {
        return envelope.Message{}, err
    }

    kemCT, ss, err := opts.Provider.Encap(ctx, keys.PeerKEMPublic)
    if err != nil {
        return envelope.Message{}, err
    }

    nonce, err := crypto.NewNonce()
    if err != nil {
        return envelope.Message{}, err
    }

    kdfInfo := kdfInfo(h.ReplayID, envelope.KindResponse)
    aeadKey, err := crypto.HKDF32(ss, opts.KDFSalt, kdfInfo)
    if err != nil {
        return envelope.Message{}, err
    }

    pl := payload.ResponsePayload{Headers: hdrs, Body: body}
    plb, err := pl.MarshalBinary()
    if err != nil {
        return envelope.Message{}, err
    }
    plct, err := crypto.Seal(aeadKey, nonce, hb, plb)
    if err != nil {
        return envelope.Message{}, err
    }

    signed := envelope.SignedBytes(hb, kemCT, nonce, plct)
    sig, err := opts.Provider.Sign(ctx, keys.SigPrivateOrSeed, signed)
    if err != nil {
        return envelope.Message{}, err
    }

    return envelope.Message{
        Header:            h,
        KEMCiphertext:     kemCT,
        Nonce:             nonce,
        PayloadCiphertext: plct,
        Signature:         sig,
    }, nil
}

func OpenResponse(ctx context.Context, opts Options, keys Keys, msg envelope.Message) (payload.ResponsePayload, error) {
    hb, err := msg.Header.MarshalBinary()
    if err != nil {
        return payload.ResponsePayload{}, err
    }

    signed := envelope.SignedBytes(hb, msg.KEMCiphertext, msg.Nonce, msg.PayloadCiphertext)
    if err := opts.Provider.Verify(ctx, keys.PeerSigPublic, signed, msg.Signature); err != nil {
        return payload.ResponsePayload{}, err
    }

    ss, err := opts.Provider.Decap(ctx, keys.KEMPrivateOrSeed, msg.KEMCiphertext)
    if err != nil {
        return payload.ResponsePayload{}, err
    }

    kdfInfo := kdfInfo(msg.Header.ReplayID, envelope.KindResponse)
    aeadKey, err := crypto.HKDF32(ss, opts.KDFSalt, kdfInfo)
    if err != nil {
        return payload.ResponsePayload{}, err
    }

    plb, err := crypto.Open(aeadKey, msg.Nonce, hb, msg.PayloadCiphertext)
    if err != nil {
        return payload.ResponsePayload{}, err
    }

    var pl payload.ResponsePayload
    if err := pl.UnmarshalBinary(plb); err != nil {
        return payload.ResponsePayload{}, err
    }
    return pl, nil
}

func kdfInfo(replayID [16]byte, kind envelope.Kind) []byte {
    // Fixed, portable, deterministic; keep it short to avoid leaking metadata.
    // [0..4) "QTL1"
    // [4)   kind
    // [5..21) replay id
    b := make([]byte, 4+1+16)
    copy(b[:4], []byte(version.ProtocolMagic))
    b[4] = byte(kind)
    copy(b[5:], replayID[:])
    return b
}

func cloneMap(m map[string]string) map[string]string {
    if m == nil {
        return map[string]string{}
    }
    out := make(map[string]string, len(m))
    for k, v := range m {
        out[k] = v
    }
    return out
}

// ReadRequestIDFromHeaderBytes is a fast-path used for replay checking before full decrypt.
func ReadRequestIDFromHeaderBytes(hb []byte) ([16]byte, error) {
    var out [16]byte
    if len(hb) < 4+2+1+1+8+16 {
        return out, errors.New("header too short")
    }
    // Layout in envelope.Header.MarshalBinary:
    // magic(4) ver(2) kind(1) mode(1) ts(8) replay(16)
    copy(out[:], hb[4+2+1+1+8:4+2+1+1+8+16])
    return out, nil
}

func ReadTimestampFromHeaderBytes(hb []byte) (int64, error) {
    if len(hb) < 4+2+1+1+8 {
        return 0, errors.New("header too short")
    }
    ts := int64(binary.BigEndian.Uint64(hb[4+2+1+1 : 4+2+1+1+8]))
    return ts, nil
}

func ValidateTimestampSkew(tsMillis int64, maxSkewMillis int64, nowMillis int64) error {
    if maxSkewMillis <= 0 {
        maxSkewMillis = int64((2 * time.Minute).Milliseconds())
    }
    delta := nowMillis - tsMillis
    if delta < 0 {
        delta = -delta
    }
    if delta > maxSkewMillis {
        return fmt.Errorf("timestamp skew too large: %dms", delta)
    }
    return nil
}
