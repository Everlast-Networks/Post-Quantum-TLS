# Third-Party Licences

This distribution includes third-party software. The licence texts are provided in the `third_party_licenses/` directory.

| Component | Utilisation | Version | Licence | Included text |
|---|---|---:|---|---|
| Go (toolchain and standard library) | Build and runtime | N/A | BSD 3-Clause | `go.license` and `go.patents` |
| golang.org/x/crypto | HPKE and supporting crypto | v0.26.0 | BSD 3-Clause | `golang.org_x_crypto.LICENSE`; `golang.org_x_crypto.PATENTS` |
| golang.org/x/sys | OS integration | v0.23.0 | BSD 3-Clause | `golang.org_x_sys.LICENSE`; `golang.org_x_sys.PATENTS` |
| gopkg.in/yaml.v3 (go-yaml/yaml) | YAML config parsing | v3.0.1 | MIT and Apache 2.0 | `gopkg.in_yaml.v3.MIT`; `gopkg.in_yaml.v3.APACHE-2.0` |
| Flask | Test backend server | N/A | BSD 3-Clause | `flask.LICENSE` |
| Werkzeug | Test backend server | N/A | BSD 3-Clause | `werkzeug.LICENSE` |
| github.com/cloudflare/circl | PQC primitives | v1.6.1 | BSD 3-Clause | `circl.license` |

Notes:
- For Go modules maintained under the Go project, the licence and patents grant match the Go project’s BSD-3-Clause and PATENTS grant. 
- Flask and Werkzeug publish their BSD-3-Clause texts in their official documentation.
