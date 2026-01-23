package app

import (
	"context"
	"errors"
	"fmt"

	circlkem "github.com/cloudflare/circl/kem"
	kemschemes "github.com/cloudflare/circl/kem/schemes"
	circlsign "github.com/cloudflare/circl/sign"
	signschemes "github.com/cloudflare/circl/sign/schemes"

	// Seed-based ML-DSA key derivation for Application mode artefacts.
	mldsa44 "github.com/cloudflare/circl/sign/mldsa/mldsa44"
	mldsa65 "github.com/cloudflare/circl/sign/mldsa/mldsa65"
	mldsa87 "github.com/cloudflare/circl/sign/mldsa/mldsa87"

	qcrypto "github.com/example/qtls/internal/crypto"
	"github.com/example/qtls/internal/version"
)

type Provider struct {
	kem circlkem.Scheme
}

func New() (*Provider, error) {
	kem := kemschemes.ByName(version.KEMName)
	if kem == nil {
		return nil, fmt.Errorf("circl kem scheme %q not found", version.KEMName)
	}
	return &Provider{kem: kem}, nil
}

func (p *Provider) Mode() qcrypto.Mode { return qcrypto.ModeApplication }

func (p *Provider) Encap(ctx context.Context, peerKEMPublic []byte) ([]byte, []byte, error) {
	pub, err := p.kem.UnmarshalBinaryPublicKey(peerKEMPublic)
	if err != nil {
		return nil, nil, err
	}
	ct, ss, err := p.kem.Encapsulate(pub)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (p *Provider) Decap(ctx context.Context, selfKEMPrivateOrSeed []byte, kemCiphertext []byte) ([]byte, error) {
	// V1 is ML-KEM-1024 only.
	//
	// CIRCL supports both packed private keys and seed-based regeneration for ML-KEM-1024.
	if len(selfKEMPrivateOrSeed) == p.kem.SeedSize() {
		_, sk := p.kem.DeriveKeyPair(selfKEMPrivateOrSeed)
		ss, err := p.kem.Decapsulate(sk, kemCiphertext)
		if err != nil {
			return nil, err
		}
		return ss, nil
	}

	priv, err := p.kem.UnmarshalBinaryPrivateKey(selfKEMPrivateOrSeed)
	if err != nil {
		return nil, fmt.Errorf(
			"unable to parse ML-KEM private key; provide packed private key bytes or a %d-byte seed: %w",
			p.kem.SeedSize(),
			err,
		)
	}
	ss, err := p.kem.Decapsulate(priv, kemCiphertext)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (p *Provider) Sign(ctx context.Context, selfSigPrivateOrSeed []byte, message []byte) ([]byte, error) {
	scheme, priv, err := selectSigSchemeFromPrivate(selfSigPrivateOrSeed)
	if err != nil {
		return nil, err
	}

	// CIRCL's generic sign.Scheme API does not return an error; it panics on
	// programmer misuse (wrong key type, unsupported context), and it returns
	// the signature bytes.
	sig := scheme.Sign(priv, message, &circlsign.SignatureOpts{Context: version.SigContext})
	return sig, nil
}

func (p *Provider) Verify(ctx context.Context, peerSigPublic []byte, message []byte, sig []byte) error {
	scheme, pub, err := selectSigSchemeFromPublic(peerSigPublic)
	if err != nil {
		return err
	}
	ok := scheme.Verify(pub, message, sig, &circlsign.SignatureOpts{
		Context: version.SigContext,
	})
	if !ok {
		return errors.New("bad signature")
	}
	return nil
}

func selectSigSchemeFromPublic(b []byte) (circlsign.Scheme, circlsign.PublicKey, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("empty ML-DSA public key")
	}

	// Try the standardised ML-DSA variants in descending strength; key sizes differ.
	for _, name := range []string{"ML-DSA-87", "ML-DSA-65", "ML-DSA-44"} {
		s := signschemes.ByName(name)
		if s == nil {
			continue
		}
		pk, err := s.UnmarshalBinaryPublicKey(b)
		if err == nil {
			return s, pk, nil
		}
	}
	return nil, nil, fmt.Errorf("unable to identify ML-DSA public key; tried 44/65/87")
}

func selectSigSchemeFromPrivate(b []byte) (circlsign.Scheme, circlsign.PrivateKey, error) {
	if len(b) == 0 {
		return nil, nil, fmt.Errorf("empty ML-DSA private key or seed")
	}

	// 1) Preferred: packed private key (CIRCL marshal format) for 87/65/44.
	for _, name := range []string{"ML-DSA-87", "ML-DSA-65", "ML-DSA-44"} {
		s := signschemes.ByName(name)
		if s == nil {
			continue
		}
		sk, err := s.UnmarshalBinaryPrivateKey(b)
		if err == nil {
			return s, sk, nil
		}
	}

	// 2) Tagged seed format (recommended):
	//    [0] = 44|65|87; [1:] = seed bytes (SeedSize).
	//
	// This solves the ambiguity created by identical seed lengths across variants.
	if len(b) == mldsa87.SeedSize+1 {
		tag := b[0]
		seedBytes := b[1:]

		switch tag {
		case 87:
			var seed [mldsa87.SeedSize]byte
			copy(seed[:], seedBytes)
			_, sk := mldsa87.NewKeyFromSeed(&seed)
			s := signschemes.ByName("ML-DSA-87")
			if s == nil {
				return nil, nil, fmt.Errorf("circl sign scheme %q not found", "ML-DSA-87")
			}
			return s, sk, nil

		case 65:
			// SeedSize is the same constant in this CIRCL revision; array length uses mldsa65.SeedSize for clarity.
			var seed [mldsa65.SeedSize]byte
			copy(seed[:], seedBytes)
			_, sk := mldsa65.NewKeyFromSeed(&seed)
			s := signschemes.ByName("ML-DSA-65")
			if s == nil {
				return nil, nil, fmt.Errorf("circl sign scheme %q not found", "ML-DSA-65")
			}
			return s, sk, nil

		case 44:
			var seed [mldsa44.SeedSize]byte
			copy(seed[:], seedBytes)
			_, sk := mldsa44.NewKeyFromSeed(&seed)
			s := signschemes.ByName("ML-DSA-44")
			if s == nil {
				return nil, nil, fmt.Errorf("circl sign scheme %q not found", "ML-DSA-44")
			}
			return s, sk, nil

		default:
			return nil, nil, fmt.Errorf("unknown ML-DSA seed tag %d; expected 44|65|87", tag)
		}
	}

	// 3) Raw seed (legacy): ambiguous across 44/65/87 in this CIRCL revision.
	// For V1, treat raw seeds as ML-DSA-87; the mint path defaults to MLDSA87.
	if len(b) == mldsa87.SeedSize {
		var seed [mldsa87.SeedSize]byte
		copy(seed[:], b)
		_, sk := mldsa87.NewKeyFromSeed(&seed)
		s := signschemes.ByName("ML-DSA-87")
		if s == nil {
			return nil, nil, fmt.Errorf("circl sign scheme %q not found", "ML-DSA-87")
		}
		return s, sk, nil
	}

	return nil, nil, fmt.Errorf("unable to identify ML-DSA private material; expected packed key or seed (raw %d bytes or tagged %d bytes)", mldsa87.SeedSize, mldsa87.SeedSize+1)
}
