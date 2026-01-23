# Project Compliance

This project is aligned with widely adopted PQC standards and guidance; it is intended to assist migration planning and incremental rollout.

## Scope and intent

QTLS Bridge is an application-level post-quantum transport intended to align with existing TLS, PKI, and cryptographic standards while enabling early adoption of NIST-standardised post-quantum algorithms. The open source project focuses on secure key establishment and authentication; full PKI lifecycle services are delivered through the commercial Certificate Authority.

## TLS RFC standards and requirements

QTLS Bridge operates in alignment with the TLS architecture defined in RFC 5246, RFC 8446, and associated specifications governing record protection, authentication, and handshake semantics. The project preserves standard TLS trust models and X.509 certificate processing, while substituting post-quantum algorithms for key establishment and signatures at the application boundary.

Certificate lifecycle controls such as OCSP and CRL distribution points are currently excluded from the open source release to keep the codebase narrow and auditable, until these modules are completed by Everlast Networks. However, these mechanisms are implemented within our commercial Certificate Authority offering, using standard RFC 6960 OCSP and RFC 5280 CRL processes, and will integrate cleanly with QTLS Bridge deployments.

## NIST and global cybersecurity alignment

QTLS Bridge is designed to support government and regulated-industry transition planning aligned with guidance from NIST, the US National Security Agency, the UK National Cyber Security Centre, and equivalent EU and Australian government programmes. These bodies consistently advise staged migration to quantum-resistant cryptography, prioritising transport security and authentication paths that protect long-lived or sensitive data.

The software is intended for environments where existing applications cannot be rapidly refactored, audited, or upgraded; it provides a controlled upgrade path that maintains compatibility with established operational and compliance frameworks.

## NIST post-quantum cryptography standards

QTLS Bridge implements algorithms selected through the NIST Post-Quantum Cryptography standardisation process, specifically:
- FIPS 203; ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) for key establishment,
- FIPS 204; ML-DSA (Module-Lattice-Based Digital Signature Algorithm) for authentication and certificate signatures.

These algorithms are explicitly referenced in current national security transition guidance, including CNSA 2.0, and are treated as first-class primitives throughout the QTLS toolchain. The project avoids experimental or pre-standard algorithms to reduce operational and compliance risk.

## Compliance boundaries

**Open source QTLS Bridge:**
- Secure application-level transport using NIST-standardised post-quantum algorithms.
- Compatibility with existing TLS trust and deployment models.
- No built-in certificate issuance, revocation, or policy enforcement.

**Commercial QTLS Certificate Authority:**
- Full X.509 issuance, renewal, revocation, OCSP, and CRL services.
- Auditable certificate lifecycle management.
- Deployment models suitable for regulated and sovereign environments.
- Management API for decoupled or automated processes, or intergration into existing public/private CA offerings.


## QTLS Standards and Compliance Coverage

| Standard or Guidance | Field | QTLS (Open Source) | Certificate Authority | Notes |
|---|---|---|---|---|
| TLS 1.2 / 1.3 (RFC 5246, RFC 8446) | Transport security | Aligned | Aligned | Preserves TLS trust and semantics |
| X.509 PKI (RFC 5280) | Certificates | Uses and validates | Full lifecycle | Standard certificate formats |
| ACME (RFC 8555) | Automated enrolment | Compatible | In Progress | Standard automation |
| OCSP (RFC 6960) | Revocation status | Not included | Included | Provided by CA |
| CRL (RFC 5280) | Revocation lists | Not included | Included | Provided by CA |
| EST (RFC 7030) | Enterprise enrolment | Compatible | Included | Enterprise environments |
| NIST FIPS 203 | PQ key establishment | Included | Included | ML-KEM |
| NIST FIPS 204 | PQ signatures | Included | Included | ML-DSA |
| NIST PQC Programme | Algorithm selection | Fully Compliant | Fully Compliant | NIST-selected only |
| CNSA 2.0 (US NSA) | National guidance | Aligned | Aligned | Transition planning |
| UK NCSC guidance | National guidance | Aligned | Aligned | Staged adoption |
| EU PQ transition work | Regional guidance | Aligned | Aligned | Transport-first focus |
| Australian Gov ISM | National policy | Aligned | Aligned | Regulated use |
| Audit logging | Operations | Minimal | Comprehensive | SIEM-ready in CA |
| HSM / PKCS#11 | Key custody | Not included | Planned | Enterprise deployments |


## Government and Commercial Standards Compliance
- **Australian government alignment**: The Australian Signals Directorate’s *Information Security Manual (ISM) – Guidelines for Cryptography* embeds post-quantum transition requirements, specifying that future cryptographic procurement and development must support approved post-quantum algorithms such as ML-KEM-1024 and ML-DSA-87 and cease traditional asymmetric algorithms beyond 2030; the Australian Cyber Security Centre’s *Planning for Post-Quantum Cryptography* further urges organisations to compile crypto inventories and prepare transition plans in advance of that deadline. This national guidance supports QTLS’s adoption of ML-KEM and ML-DSA for quantum-resilient key exchange and digital signatures in communications security. Everlast Networks has also previously submitted several consultations to the Australian Department of Home Affairs on the direction and future of Secure Communications within Government, Private Sector, and Defence. (https://www.cyber.gov.au/business-government/secure-design/planning-for-post-quantum-cryptography)

- **United States Government / NIST guidance**: NIST has finalised post-quantum cryptography standards including ML-KEM and ML-DSA as FIPS standards and encourages transition planning to quantum-resistant cryptography; QTLS’s implementation of these NIST-approved algorithms aligns with U.S. government expectations for communications security. (https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)

- **United Kingdom Government guidance**: The UK’s National Cyber Security Centre (NCSC) provides guidance on preparing for post-quantum cryptography migration, referencing NIST’s standardised PQC algorithms as suitable and recommending timeline-aware migration planning, consistent with QTLS’s quantum-resistant algorithm choices. (https://www.ncsc.gov.uk/whitepaper/next-steps-preparing-for-post-quantum-cryptography)

- **Canada Government guidance**: The Canadian Centre for Cyber Security’s roadmap for migration to post-quantum cryptography recommends phased PQC adoption—including standardised algorithms—to protect federal systems; the inclusion of standardised PQC aligns with QTLS’s ML-KEM and ML-DSA approach. (https://www.cyber.gc.ca/en/guidance/roadmap-migration-post-quantum-cryptography-government-canada-itsm40001)

- **NATO quantum strategy**: NATO’s quantum technologies strategy recognises post-quantum cryptography as critical for future communications security against quantum threats and supports allied cooperation on PQC transition; QTLS’s adoption of quantum-resistant primitives aligns with this collective defence perspective. (https://www.nato.int/en/about-us/official-texts-and-resources/official-texts/2024/01/16/summary-of-natos-quantum-technologies-strategy)

- **India PQC technical report**: India’s Telecommunication Engineering Centre has published a technical report on migration to post-quantum cryptography that references NIST-standardised algorithms such as ML-KEM and ML-DSA as part of the evolving landscape and suggests adopting these standards for quantum-safe systems; this informs how QTLS’s deployment can be compatible with Indian telecom engineering guidance. (https://www.tec.gov.in/pdf/TR/Final%20technical%20report%20on%20migration%20to%20PQC%2028-03-25.pdf)

- **NIST / U.S. National Security perspective**: The United States’ quantum readiness and cryptographic migration guidance (including directives such as National Security Memorandum 10) direct federal agencies towards PQC adoption with timelines that influence allied practices; QTLS’s ML-KEM/ML-DSA selection adheres to these PQC priority standards. (https://www.rand.org/pubs/commentary/2025/06/us-allied-militaries-must-prepare-for-the-quantum-threat.html)


## Defence Force Alignments
- **US Department of War guidance**: The US Department of War has directed all components to assess and transition towards quantum-resistant cryptography, initiating full cryptographic inventories and migration planning using NIST-approved algorithms for key exchange and signatures, including PQC approaches relevant to ML-KEM/ML-DSA; this aligns with QTLS’s adoption of those standards. (https://www.meritalk.com/articles/pentagon-cio-orders-rapid-shift-to-post-quantum-crypto)

- **UK Ministry of Defence / NCSC defence context**: The UK’s National Cyber Security Centre, supporting cyber guidance including for defence, has outlined PQC migration activity timelines and budgets (e.g. JCKP investment) to protect MOD systems against future quantum threats and benchmarks readiness milestones toward 2035; adopting NIST-aligned PQC primitives like ML-KEM and ML-DSA is consistent with this stance. (https://www.ncsc.gov.uk/collection/ncsc-annual-review-2025/chapter-03-keeping-pace-with-evolving-technology/migrating-to-post-quantum-cryptography)

- **US DoD warfighter memo and strategic intent**: A DoD memorandum titled *Preparing for Migration to Post Quantum Cryptography* frames PQC readiness as critical for safeguarding communications and warfighter systems, urging comprehensive planning and migration across IT and tactical systems, drawing on NIST’s standards basis (ML-KEM/ML-DSA) to future-proof defence networks. (https://www.dmi-ida.org/knowledge-base-detail/Preparing-for-Migration-to-Post-Quantum-Cryptography-Memorandum)

- **Australian Department of Defence alignment**: Australian Defence initiatives reflect a forward stance on secure communications and emerging quantum threats. New projects such as LAND 4140 (Land C4I Modernisation) focus on upgraded command, control, communications and computing capabilities, and while publicly available tender details do not specify post-quantum algorithms, the programme’s secure communications remit implies alignment with national PQC expectations, including ASD’s ISM transition requirements. In parallel, the Defence Science and Technology Group’s quantum-secured timing network project, funded by the Australian Army, explores quantum technologies relevant to resilient secure communications in contested environments, complementing broader post-quantum cryptography planning by national authorities. (https://www.ex2.com.au/news/gme-and-hanwha-sign-teaming-agreement-for-land4140)

- **NATO defence perspective**: NATO’s Quantum Technologies Strategy highlights post-quantum cryptography as a key element of allied communications security in the quantum era, advocating cooperation on quantum-resistant cryptographic transitions and safeguarding command, control and secure communications; QTLS’s PQC share of algorithms fits within this collective allied view. (https://www.nato.int/cps/en/natohq/official_texts_221777.htm)

- **Indian defence research activity (contextual)**: While India has not yet issued a formal defence PQC migration standard, the Indian Army’s dedicated quantum research efforts and operational focus on hybrid quantum security (including PQC) signal evolving military awareness of quantum threats and the need for post-quantum readiness that would embrace standards like those underpinning ML-KEM/ML-DSA. (*Indicative summary drawn from public analysis of India’s research and defence quantum cyber work*)