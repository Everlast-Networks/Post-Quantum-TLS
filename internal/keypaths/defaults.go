package keypaths

import (
	"os"
	"path/filepath"
)

type Paths struct {
	SelfKEMPrivateOrSeed string
	PeerKEMPublic        string

	SelfSigPrivateOrSeed string
	PeerSigPublic        string
}

// ServerDefaults for V1: server has its own KEM+SIG; only peer SIG is required.
// Peer KEM is not used on the server path.
func ServerDefaults(certsDir string) Paths {
	join := func(name string) string {
		if name == "" {
			return ""
		}
		if certsDir == "" {
			return name
		}
		return filepath.Join(certsDir, name)
	}

	p := Paths{
		SelfKEMPrivateOrSeed: join("server.kem.key.der"),
		SelfSigPrivateOrSeed: join("server.sig.key.der"),
		PeerSigPublic:        join("client.pub.der"),
		// PeerKEMPublic intentionally left empty in V1
	}

	// Keep the firstExisting helper if you want to probe .der vs .pem; for now
	// we hard-code DER names from the minting tool; simpler and explicit.
	if _, err := os.Stat(p.SelfKEMPrivateOrSeed); err != nil {
		p.SelfKEMPrivateOrSeed = join("server.kem.key")
	}
	if _, err := os.Stat(p.SelfSigPrivateOrSeed); err != nil {
		p.SelfSigPrivateOrSeed = join("server.sig.key")
	}
	if _, err := os.Stat(p.PeerSigPublic); err != nil {
		p.PeerSigPublic = join("client.sig.pub.der")
	}

	return p
}

func ClientDefaults(certsDir string) Paths {
	join := func(name string) string {
		if name == "" {
			return ""
		}
		if certsDir == "" {
			return name
		}
		return filepath.Join(certsDir, name)
	}

	p := Paths{
		// Client: no KEM private in V1; it only needs peer KEM public.
		PeerKEMPublic:        join("server.kem.pub.der"),
		SelfSigPrivateOrSeed: join("client.key.der"),
		PeerSigPublic:        join("server.sig.pub.der"),
	}

	if _, err := os.Stat(p.SelfSigPrivateOrSeed); err != nil {
		p.SelfSigPrivateOrSeed = join("client.key")
	}
	if _, err := os.Stat(p.PeerKEMPublic); err != nil {
		p.PeerKEMPublic = join("server.kem.pub")
	}
	if _, err := os.Stat(p.PeerSigPublic); err != nil {
		p.PeerSigPublic = join("server.sig.pub")
	}

	return p
}
