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

package certinfo

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/example/qtls/internal/osslutil"
)

type VerifyPurpose string

const (
	VerifyPurposeServer VerifyPurpose = "sslserver"
	VerifyPurposeClient VerifyPurpose = "sslclient"
)

func VerifyChainOpenSSL(
	ctx context.Context,
	opensslCmd string,
	opensslConf string,
	leafPath string,
	rootPath string,
	chainPath string,
	purpose VerifyPurpose,
	verifyHostname string,
	now time.Time,
) error {
	if opensslCmd == "" {
		opensslCmd = "openssl"
	}
	if leafPath == "" || rootPath == "" {
		return errors.New("missing leaf or root path")
	}

	args := []string{
		"verify",
		"-CAfile", rootPath,
	}
	if chainPath != "" {
		args = append(args, "-untrusted", chainPath)
	}
	if purpose != "" {
		args = append(args, "-purpose", string(purpose))
	}
	if verifyHostname != "" {
		args = append(args, "-verify_hostname", verifyHostname)
	}
	_ = now
	args = append(args, leafPath)

	cmd := exec.CommandContext(ctx, opensslCmd, args...)
	cmd.Env = osslutil.EnvWithOpenSSLConf(os.Environ(), opensslConf)

	out, err := cmd.CombinedOutput()
	if err != nil {
		s := strings.TrimSpace(string(out))
		if s == "" {
			s = err.Error()
		}
		return fmt.Errorf("openssl verify failed: %s", s)
	}
	return nil
}

func ExtractCertPublicKeyOpenSSL(
	ctx context.Context,
	opensslCmd string,
	opensslConf string,
	certPath string,
) ([]byte, error) {
	if opensslCmd == "" {
		opensslCmd = "openssl"
	}
	if certPath == "" {
		return nil, errors.New("missing cert path")
	}

	cmd := exec.CommandContext(ctx, opensslCmd, "x509", "-in", certPath, "-pubkey", "-noout")
	cmd.Env = osslutil.EnvWithOpenSSLConf(os.Environ(), opensslConf)

	out, err := cmd.CombinedOutput()
	if err != nil {
		s := strings.TrimSpace(string(out))
		if s == "" {
			s = err.Error()
		}
		return nil, fmt.Errorf("openssl x509 -pubkey failed: %s", s)
	}
	return out, nil
}
