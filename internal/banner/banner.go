package banner

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Startup is a boot-time summary for operators.
//
// It deliberately does not touch slog handlers; the structured JSON stream stays
// intact for log shipping and audit. The banner is intended for an interactive
// terminal at bring-up time.

type Startup struct {
	Service string
	Build   string
	Mode    string

	// These are displayed as a single line; leave empty if not relevant.
	ListenAddr string
	Upstream   string

	CertsDir string

	// Schemes is a human string, for example: "ML-KEM-1024 / ML-DSA-87".
	Schemes string
}

// Print writes a one-time, terminal-friendly startup banner.
func Print(w io.Writer, s Startup) {
	if w == nil {
		w = os.Stdout
	}

	now := time.Now().In(time.Local)
	var buf bytes.Buffer

	buf.WriteString("\n")
	buf.WriteString(">> STARTING QTLS\n")

	if s.Build != "" {
		fmt.Fprintf(&buf, "// BUILD %s\n", safeOneLine(s.Build))
	} else {
		buf.WriteString("// BUILD (unlabelled)\n")
	}

	if s.Service != "" {
		fmt.Fprintf(&buf, "// SERVICE: %s\n", safeOneLine(s.Service))
	}
	if s.Mode != "" {
		fmt.Fprintf(&buf, "// MODE SELECTED: %s\n", safeOneLine(strings.ToUpper(s.Mode)))
	}
	fmt.Fprintf(&buf, "// BOOT TIME: %s\n", now.Format(time.RFC3339))

	certs, chainPath, chainErr := readChainPEM(s.CertsDir)
	if chainErr == nil && len(certs) > 0 {
		// Convention: many deployments place the trust anchor last.
		root := certs[len(certs)-1]

		fmt.Fprintf(&buf, "// CERT LOADED - CA ORG : %s\n", safeOneLine(pickOrg(root.Subject)))
		fmt.Fprintf(&buf, "// CERT SUBJECT: %s\n", safeOneLine(nameSummaryPipes(root.Subject)))
		fmt.Fprintf(&buf, "// CERT ISSUER : %s\n", safeOneLine(nameSummaryPipes(root.Issuer)))
		fmt.Fprintf(&buf, "// CERT SERIAL : %s\n", safeOneLine(shortSerial(root.SerialNumber.String())))
		fmt.Fprintf(&buf, "// NOT BEFORE  : %s\n", root.NotBefore.UTC().Format(time.RFC3339))
		fmt.Fprintf(&buf, "// EXPIRES     : %s\n", root.NotAfter.UTC().Format(time.RFC3339))

		sum := sha256.Sum256(root.Raw)
		fmt.Fprintf(&buf, "// SHA256 FP   : %s\n", hex.EncodeToString(sum[:]))

		if chainPath != "" {
			fmt.Fprintf(&buf, "// CHAIN FILE  : %s\n", safeOneLine(chainPath))
		}
		fmt.Fprintf(&buf, "// CHAIN CERTS : %d\n", len(certs))
	} else {
		if s.CertsDir != "" {
			fmt.Fprintf(&buf, "// CERT LOADED - DETAILS UNAVAILABLE (certs_dir=%s)\n", safeOneLine(s.CertsDir))
		} else {
			buf.WriteString("// CERT LOADED - DETAILS UNAVAILABLE\n")
		}
	}

	if s.Schemes != "" {
		fmt.Fprintf(&buf, ">> SELECTED %s\n", safeOneLine(s.Schemes))
	}

	switch {
	case s.ListenAddr != "" && s.Upstream != "":
		if strings.Contains(strings.ToLower(s.Service), "client") {
			fmt.Fprintf(&buf, ">> PROXY LISTENING ON %s <=> QTLS %s\n", safeOneLine(s.ListenAddr), safeOneLine(s.Upstream))
		} else {
			fmt.Fprintf(&buf, ">> SERVER MOUNTED LISTENING ON %s <=> UPSTREAM %s\n", safeOneLine(s.ListenAddr), safeOneLine(s.Upstream))
		}
	case s.ListenAddr != "":
		fmt.Fprintf(&buf, ">> LISTENING ON %s\n", safeOneLine(s.ListenAddr))
	case s.Upstream != "":
		fmt.Fprintf(&buf, ">> UPSTREAM %s\n", safeOneLine(s.Upstream))
	}

	buf.WriteString(">> SYSTEM READY\n\n")

	_, _ = w.Write(buf.Bytes())
}

// GuessSchemes provides a best-effort scheme string by inspecting key file sizes.
// It is intentionally conservative; if it cannot identify a scheme, it returns a
// shorter string rather than guessing.
func GuessSchemes(kemPubPath, sigPubPath string) string {
	kem := "ML-KEM-1024" // QTLS v1 is hard-coded to ML-KEM-1024 ONLY. MAXIMUM SECURITY!

	mldsa := "ML-DSA"
	if sigPubPath != "" {
		if st, err := os.Stat(sigPubPath); err == nil {
			switch st.Size() {
			case 1312:
				mldsa = "ML-DSA-44"
			case 1952:
				mldsa = "ML-DSA-65"
			case 2592:
				mldsa = "ML-DSA-87"
			}
		}
	}

	// If the caller passes no paths, we still show the expected defaults.
	_ = kemPubPath
	return kem + " / " + mldsa
}

func readChainPEM(certsDir string) ([]*x509.Certificate, string, error) {
	if certsDir == "" {
		return nil, "", fmt.Errorf("empty certsDir")
	}
	chainPath := filepath.Join(certsDir, "chain.pem")
	b, err := os.ReadFile(chainPath)
	if err != nil {
		return nil, chainPath, err
	}

	var certs []*x509.Certificate
	rest := b
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			break
		}
		rest = r
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			// Best-effort: unknown or vendor OIDs can fail parsing on some toolchains.
			continue
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, chainPath, fmt.Errorf("no parseable certificates in chain.pem")
	}
	return certs, chainPath, nil
}

func safeOneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.TrimSpace(s)
	return s
}

func pickOrg(n pkix.Name) string {
	if len(n.Organization) > 0 {
		return n.Organization[0]
	}
	if n.CommonName != "" {
		return n.CommonName
	}
	return "(unlisted)"
}

func nameSummaryPipes(n pkix.Name) string {
	parts := make([]string, 0, 8)
	add := func(k, v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		parts = append(parts, k+": "+v)
	}

	add("CN", n.CommonName)
	if len(n.OrganizationalUnit) > 0 {
		add("OU", strings.Join(n.OrganizationalUnit, "/"))
	}
	if len(n.Organization) > 0 {
		add("O", strings.Join(n.Organization, "/"))
	}
	if len(n.Locality) > 0 {
		add("L", strings.Join(n.Locality, "/"))
	}
	if len(n.Province) > 0 {
		add("ST", strings.Join(n.Province, "/"))
	}
	if len(n.Country) > 0 {
		add("C", strings.Join(n.Country, "/"))
	}

	if len(parts) == 0 {
		return "(unlisted)"
	}
	return strings.Join(parts, " | ")
}

func shortSerial(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 20 {
		return s
	}
	return s[:10] + "..." + s[len(s)-10:]
}
