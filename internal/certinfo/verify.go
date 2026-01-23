package certinfo

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func VerifyChainNow(
	certsDir string,
	leafName string,
	rootName string,
	chainName string,
	now time.Time,
	eku []x509.ExtKeyUsage,
) error {
	leafDER, err := readFirstCertDER(filepath.Join(certsDir, leafName))
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}

	roots := x509.NewCertPool()
	if err := appendPEM(roots, filepath.Join(certsDir, rootName)); err != nil {
		return err
	}

	inters := x509.NewCertPool()
	if err := appendPEM(inters, filepath.Join(certsDir, chainName)); err != nil {
		return err
	}

	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     eku,
	})
	return err
}

func appendPEM(pool *x509.CertPool, path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if ok := pool.AppendCertsFromPEM(b); !ok {
		return fmt.Errorf("no certs parsed from %s", path)
	}
	return nil
}

func readFirstCertDER(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE block in %s", path)
	}
	return blk.Bytes, nil
}
