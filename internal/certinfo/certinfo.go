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
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "os"
    "path/filepath"
    "time"
)

type Info struct {
    File string
    Subject string
    Issuer  string
    NotBefore time.Time
    NotAfter  time.Time
    DNSNames  []string
    IPAddresses []string
}

func ReadChain(certsDir string) ([]Info, error) {
    chainPath := filepath.Join(certsDir, "chain.pem")
    b, err := os.ReadFile(chainPath)
    if err != nil {
        // best-effort; if there is no chain.pem, do nothing
        return nil, nil
    }

    var infos []Info
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
        cert, err := x509.ParseCertificate(blk.Bytes)
        if err != nil {
            // Unknown PQ OIDs can fail parsing on some Go versions; keep running.
            continue
        }
        ii := Info{
            File: chainPath,
            Subject: cert.Subject.String(),
            Issuer:  cert.Issuer.String(),
            NotBefore: cert.NotBefore,
            NotAfter: cert.NotAfter,
            DNSNames: cert.DNSNames,
        }
        for _, ip := range cert.IPAddresses {
            ii.IPAddresses = append(ii.IPAddresses, ip.String())
        }
        infos = append(infos, ii)
    }
    return infos, nil
}

func (i Info) String() string {
    return fmt.Sprintf("subject=%q issuer=%q not_after=%s dns=%v ip=%v",
        i.Subject, i.Issuer, i.NotAfter.UTC().Format(time.RFC3339), i.DNSNames, i.IPAddresses)
}
