//go:build windows

package system

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	qcrypto "github.com/example/qtls/internal/crypto"
)

// This file implements "system" mode on Windows using CNG (bcrypt.dll).
// Warning: This functionality is tagged as experimental, do not use it on any production systems.
//
// V1 scope:
//   * ML-KEM-1024 only (key agreement)
//   * Signature operations remain in application mode for now; key import for ML-DSA via CNG is volatile
//     across prerelease builds and will be hardened in V2.
//
// TODO List:
// 1) Finish testing ML-KEM Keying.
// 2) Finish testing ML-DSA Signature verification.
// 3) Finish documentation and benchmarking.
//

const (
	// Algorithm identifiers as used by BCryptOpenAlgorithmProvider.
	algMLKEM = "ML-KEM"

	// BCRYPT_MLKEM_KEY_BLOB constants.
	mlkemPublicMagic      = 0x504B4C4D // MLKP
	mlkemPrivateMagic     = 0x524B4C4D // MLKR
	mlkemPrivateSeedMagic = 0x534B4C4D // MLKS

	// Parameter set string; UTF-16 with NUL terminator is 10 bytes for "1024".
	mlkemParamSet = "1024"

	// ML-KEM shared secret length is fixed at 32 bytes.
	// This is a property of the standard, and is identical across parameter sets.
	mlkemSharedSecretLen = 32
)

type Provider struct{}

func New() *Provider { return &Provider{} }

func Supported() (bool, string) {
	// Avoid a hard crash if the entrypoint is missing on a given build.
	// syscall.LazyProc exposes Find() for pre-flight resolution. :contentReference[oaicite:1]{index=1}
	if err := procBCryptOpenAlgorithmProvider.Find(); err != nil {
		return false, fmt.Sprintf("bcrypt entrypoint missing: BCryptOpenAlgorithmProvider; err=%v", err)
	}
	if err := procBCryptCloseAlgorithmProvider.Find(); err != nil {
		return false, fmt.Sprintf("bcrypt entrypoint missing: BCryptCloseAlgorithmProvider; err=%v", err)
	}

	hAlg, st := bcryptOpenAlgorithmProvider(algMLKEM)
	if st == 0 {
		_ = bcryptCloseAlgorithmProvider(hAlg)
		return true, "Windows CNG reports ML-KEM support"
	}

	// BCryptOpenAlgorithmProvider returns NTSTATUS; STATUS_SUCCESS is 0. :contentReference[oaicite:2]{index=2}
	return false, fmt.Sprintf("Windows CNG does not report ML-KEM support; NTSTATUS=0x%08X", uint32(st))
}

func (p *Provider) Mode() qcrypto.Mode { return qcrypto.ModeSystem }

func (p *Provider) Supported(ctx context.Context) (bool, string) {
	_ = ctx
	return Supported()
}

func (p *Provider) Encap(ctx context.Context, peerKEMPublic []byte) ([]byte, []byte, error) {
	hAlg, st := bcryptOpenAlgorithmProvider(algMLKEM)
	if st != 0 {
		return nil, nil, fmt.Errorf("bcrypt open algorithm %q failed; NTSTATUS=0x%08X", algMLKEM, uint32(st))
	}
	defer func() { _ = bcryptCloseAlgorithmProvider(hAlg) }()

	hKey, st := importMLKEMKey(hAlg, mlkemPublicMagic, peerKEMPublic)
	if st != 0 {
		return nil, nil, fmt.Errorf("bcrypt import ML-KEM public key failed; NTSTATUS=0x%08X", uint32(st))
	}
	defer func() { _ = bcryptDestroyKey(hKey) }()

	// Query ciphertext size.
	ctLen, st := bcryptEncapsulateSize(hKey, true)
	if st != 0 {
		return nil, nil, fmt.Errorf("bcrypt encapsulate size query failed; NTSTATUS=0x%08X", uint32(st))
	}
	// Query secret size.
	ssLen, st := bcryptEncapsulateSize(hKey, false)
	if st != 0 {
		return nil, nil, fmt.Errorf("bcrypt secret size query failed; NTSTATUS=0x%08X", uint32(st))
	}

	ct := make([]byte, ctLen)
	ss := make([]byte, ssLen)

	st = bcryptEncapsulate(hKey, ct, ss)
	if st != 0 {
		return nil, nil, fmt.Errorf("bcrypt encapsulate failed; NTSTATUS=0x%08X", uint32(st))
	}
	return ct, ss, nil
}

func (p *Provider) Decap(ctx context.Context, selfKEMPrivateOrSeed []byte, ct []byte) ([]byte, error) {
	hAlg, st := bcryptOpenAlgorithmProvider(algMLKEM)
	if st != 0 {
		return nil, fmt.Errorf("bcrypt open algorithm %q failed; NTSTATUS=0x%08X", algMLKEM, uint32(st))
	}
	defer func() { _ = bcryptCloseAlgorithmProvider(hAlg) }()

	// If the input is a 64-byte concatenation of d||z, treat it as a seed; otherwise treat it as the
	// byte-encoded ML-KEM private key.
	magic := uint32(mlkemPrivateMagic)
	if len(selfKEMPrivateOrSeed) == 64 {
		magic = mlkemPrivateSeedMagic
	}

	hKey, st := importMLKEMKey(hAlg, magic, selfKEMPrivateOrSeed)
	if st != 0 {
		return nil, fmt.Errorf("bcrypt import ML-KEM private key failed; NTSTATUS=0x%08X", uint32(st))
	}
	defer func() { _ = bcryptDestroyKey(hKey) }()

	ss := make([]byte, mlkemSharedSecretLen)
	st = bcryptDecapsulate(hKey, ct, ss)
	if st != 0 {
		return nil, fmt.Errorf("bcrypt decapsulate failed; NTSTATUS=0x%08X", uint32(st))
	}
	return ss, nil
}

func (p *Provider) Sign(ctx context.Context, selfSigPrivate []byte, msg []byte) ([]byte, error) {
	return nil, errors.New("system mode signature is not enabled in V1; use application or openssl")
}

func (p *Provider) Verify(ctx context.Context, peerSigPublic []byte, msg []byte, sig []byte) error {
	return errors.New("system mode signature is not enabled in V1; use application or openssl")
}

// ---- bcrypt.dll bindings ----

type (
	bcryptAlgHandle uintptr
	bcryptKeyHandle uintptr
)

var (
	bcryptDLL = syscall.NewLazyDLL("bcrypt.dll")

	procBCryptOpenAlgorithmProvider  = bcryptDLL.NewProc("BCryptOpenAlgorithmProvider")
	procBCryptCloseAlgorithmProvider = bcryptDLL.NewProc("BCryptCloseAlgorithmProvider")
	procBCryptImportKeyPair          = bcryptDLL.NewProc("BCryptImportKeyPair")
	procBCryptDestroyKey             = bcryptDLL.NewProc("BCryptDestroyKey")
	procBCryptEncapsulate            = bcryptDLL.NewProc("BCryptEncapsulate")
	procBCryptDecapsulate            = bcryptDLL.NewProc("BCryptDecapsulate")
)

func bcryptOpenAlgorithmProvider(alg string) (bcryptAlgHandle, syscall.Errno) {
	algUTF16, _ := syscall.UTF16PtrFromString(alg)
	var h bcryptAlgHandle

	// LazyProc.Call returns (r1, r2, lastErr); lastErr is not needed for NTSTATUS-based CNG calls. :contentReference[oaicite:3]{index=3}
	r1, _, _ := procBCryptOpenAlgorithmProvider.Call(
		uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(algUTF16)),
		0,
		0,
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return h, 0
}

func bcryptCloseAlgorithmProvider(h bcryptAlgHandle) syscall.Errno {
	r1, _, _ := procBCryptCloseAlgorithmProvider.Call(uintptr(h), 0)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return 0
}

func bcryptDestroyKey(h bcryptKeyHandle) syscall.Errno {
	r1, _, _ := procBCryptDestroyKey.Call(uintptr(h))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return 0
}

// ML-KEM key blob header.
//
// Followed by:
//   - UTF-16LE parameterSet including NUL terminator
//   - key bytes
type mlkemKeyBlob struct {
	Magic        uint32
	ParamSetSize uint32
	KeySize      uint32
}

func importMLKEMKey(hAlg bcryptAlgHandle, magic uint32, keyBytes []byte) (bcryptKeyHandle, syscall.Errno) {
	blob, err := buildMLKEMBlob(magic, mlkemParamSet, keyBytes)
	if err != nil {
		return 0, syscall.Errno(syscall.EINVAL)
	}

	// Windows uses string constants in bcrypt.h; the underlying string values are not stable in public
	// documentation. We try a short list that matches common CNG naming conventions.
	candidates := []string{
		"MLKEMPUBLICBLOB",
		"MLKEMENCAPSULATIONBLOB",
		"BCRYPT_MLKEM_PUBLIC_BLOB",
		"BCRYPT_MLKEM_ENCAPSULATION_BLOB",
		"MLKEMPRIVATEBLOB",
		"MLKEMDECAPSULATIONBLOB",
		"BCRYPT_MLKEM_PRIVATE_BLOB",
		"BCRYPT_MLKEM_DECAPSULATION_BLOB",
		"MLKEMPRIVATESEEDBLOB",
		"BCRYPT_MLKEM_PRIVATE_SEED_BLOB",
	}

	var last syscall.Errno
	for _, blobType := range candidates {
		psz, _ := syscall.UTF16PtrFromString(blobType)
		var hKey bcryptKeyHandle
		r1, _, _ := procBCryptImportKeyPair.Call(
			uintptr(hAlg),
			0,
			uintptr(unsafe.Pointer(psz)),
			uintptr(unsafe.Pointer(&hKey)),
			uintptr(unsafe.Pointer(&blob[0])),
			uintptr(len(blob)),
			0,
		)
		if r1 == 0 {
			return hKey, 0
		}
		last = syscall.Errno(r1)
	}
	return 0, last
}

func buildMLKEMBlob(magic uint32, paramSet string, keyBytes []byte) ([]byte, error) {
	ps, err := utf16ZBytes(paramSet)
	if err != nil {
		return nil, err
	}
	hdr := mlkemKeyBlob{
		Magic:        magic,
		ParamSetSize: uint32(len(ps)),
		KeySize:      uint32(len(keyBytes)),
	}
	out := make([]byte, int(unsafe.Sizeof(hdr))+len(ps)+len(keyBytes))
	*(*mlkemKeyBlob)(unsafe.Pointer(&out[0])) = hdr
	copy(out[int(unsafe.Sizeof(hdr)):], ps)
	copy(out[int(unsafe.Sizeof(hdr))+len(ps):], keyBytes)
	return out, nil
}

func utf16ZBytes(s string) ([]byte, error) {
	u16, err := syscall.UTF16FromString(s)
	if err != nil {
		return nil, err
	}
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		b[i*2+0] = byte(v)
		b[i*2+1] = byte(v >> 8)
	}
	return b, nil
}

func bcryptEncapsulateSize(hKey bcryptKeyHandle, wantCiphertext bool) (int, syscall.Errno) {
	// When pbSecretKey and pbCipherText are NULL, pcbSecretKey and pcbCipherText receive the required lengths.
	var ssLen uint32
	var ctLen uint32
	r1, _, _ := procBCryptEncapsulate.Call(
		uintptr(hKey),
		0,
		0,
		uintptr(unsafe.Pointer(&ssLen)),
		0,
		0,
		uintptr(unsafe.Pointer(&ctLen)),
		0,
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	if wantCiphertext {
		return int(ctLen), 0
	}
	return int(ssLen), 0
}

func bcryptEncapsulate(hKey bcryptKeyHandle, ct []byte, ss []byte) syscall.Errno {
	var ssLen uint32
	var ctLen uint32
	r1, _, _ := procBCryptEncapsulate.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&ss[0])),
		uintptr(len(ss)),
		uintptr(unsafe.Pointer(&ssLen)),
		uintptr(unsafe.Pointer(&ct[0])),
		uintptr(len(ct)),
		uintptr(unsafe.Pointer(&ctLen)),
		0,
	)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	if int(ssLen) != len(ss) {
		return syscall.Errno(syscall.EINVAL)
	}
	if int(ctLen) != len(ct) {
		return syscall.Errno(syscall.EINVAL)
	}
	return 0
}

func bcryptDecapsulate(hKey bcryptKeyHandle, ct []byte, ss []byte) syscall.Errno {
	var ssLen uint32
	r1, _, _ := procBCryptDecapsulate.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(&ct[0])),
		uintptr(len(ct)),
		uintptr(unsafe.Pointer(&ss[0])),
		uintptr(len(ss)),
		uintptr(unsafe.Pointer(&ssLen)),
		0,
	)
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	if int(ssLen) != len(ss) {
		return syscall.Errno(syscall.EINVAL)
	}
	return 0
}
