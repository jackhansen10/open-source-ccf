# OpenCCF — FedRAMP / Government Edition

**An extended Common Controls Framework for SaaS companies pursuing FedRAMP High authorization, building on the commercial OpenCCF baseline.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)]()
[![Base](https://img.shields.io/badge/base-OpenCCF%20Commercial%20v1.0.0-orange.svg)]()

---

## What's Different from the Commercial Edition

The commercial OpenCCF covers the frameworks most SaaS companies need for enterprise sales. This edition layers on what you need to sell to the US federal government through FedRAMP High authorization.

### By the Numbers

| Metric | Commercial | FedRAMP/Gov |
|---|---|---|
| Total Controls | 103 | 122 |
| FedRAMP-specific additions | — | 31 |
| Frameworks Mapped | 10 | 11 (adds FedRAMP) |
| Total Mappings | 1,161 | 1,707 |
| NIST 800-53 depth | Moderate-ish | High baseline |

### What Changed

**New controls (31 additions)** cover requirements that don't exist in the commercial world or that FedRAMP makes materially more prescriptive:

- **SSP and Authorization Boundary** — You must document your system in excruciating detail
- **FIPS 199 Security Categorization** — Impact levels drive everything
- **Authorization to Operate (ATO)** — Formal risk acceptance from the Authorizing Official
- **FIPS 140-2/3 Validated Crypto** — "AES-256" isn't enough; the *module* must be validated
- **Session Management** — FedRAMP specifies exact timeout values (15 min lock, 30 min terminate, 3 concurrent sessions)
- **Separation of Duties** — Explicit, enforced, documented
- **Information Flow Enforcement** — Boundary-level data flow controls
- **Login Banners** — Yes, the government really cares about this
- **US-CERT/CISA Incident Reporting** — 1-hour reporting for certain incident categories
- **POA&M Management** — The tracking mechanism for everything
- **Continuous Monitoring (ConMon)** — Monthly deliverables to FedRAMP PMO
- **Supply Chain Risk Management** — NIST 800-161 alignment
- **Alternate Processing Sites** — Geographic redundancy requirements
- **Personnel Screening** — Position sensitivity-based, beyond standard background checks

**Enhanced controls** — Many commercial controls got deeper NIST 800-53 enhancements (more control enhancements mapped) and FedRAMP-specific parameter values.

Controls carry a `fedramp_delta` field:
- `false` = exists in the commercial baseline (may have expanded 800-53 mappings)
- `true` = new or materially enhanced for FedRAMP High

---

## Files in This Directory

| File | Description |
|---|---|
| `openccf-fedramp.json` | Full CCF with all 122 controls and 11-framework mappings |
| `openccf-fedramp.csv` | Flat CSV for spreadsheet and GRC tool import |
| `fedramp-parameters.json` | FedRAMP Organization-Defined Parameters (ODPs) and additional requirements |
| `generate_ccf_fedramp.py` | Source-of-truth generator script |
| `README.md` | This file |

### `fedramp-parameters.json` — Why This Matters

NIST 800-53 controls often say "organization-defined [parameter]." FedRAMP doesn't leave those blank — they specify exact values. Your 3PAO will test against these.

Examples:
- **AC-7**: Lock after 3 failed attempts in 15 minutes
- **AC-11**: Session lock after 15 minutes of inactivity
- **AU-11**: Retain logs for 1 year, 90 days online
- **SI-2**: Patch critical vulns within 30 days, high within 60, moderate within 90
- **SC-13**: FIPS 140-2/3 validated modules only
- **IR-6**: Report to US-CERT within 1 hour

The parameters file contains 30+ FedRAMP-specified ODPs plus the additional FedRAMP requirements (ConMon deliverables, authorization boundary, integrated inventory workbook, digital identity requirements).

---

## Frameworks Mapped

All 10 frameworks from the commercial edition, plus FedRAMP as a distinct mapping column:

| Framework | Version | Notes |
|---|---|---|
| SOC 2 TSC | 2017 | Still relevant — many agencies want SOC 2 alongside FedRAMP |
| ISO 27001 | 2022 | International enterprise deals |
| ISO 27017 | 2015 | Cloud security extensions |
| ISO 27018 | 2019 | PII in cloud |
| NIST CSF | 2.0 | Risk framework reference |
| **NIST 800-53** | **Rev 5 High** | **Deepened to High baseline with enhancements** |
| **FedRAMP** | **High (Rev 5)** | **FedRAMP-specific additional requirements** |
| PCI DSS | 4.0 | Payment processing |
| HIPAA | 45 CFR 164 | Healthcare |
| GDPR | EU 2016/679 | EU privacy |
| CCPA/CPRA | Cal. Civ. Code §1798 | US privacy |

### Why FedRAMP Is a Separate Column from NIST 800-53

Because FedRAMP adds requirements *on top of* NIST 800-53. The FedRAMP column captures:
- FedRAMP-specific additional requirements (e.g., ConMon deliverables)
- References to FedRAMP templates and guidance documents
- Parameter values that differ from or extend the base NIST requirement

If a control maps to `nist_800_53: ["RA-5"]` and `fedramp: ["RA-5", "FedRAMP Vuln Scan Requirements"]`, that tells you there are FedRAMP-specific scanning cadence and reporting requirements beyond what NIST 800-53 alone requires.

---

## Domain Breakdown

| Domain | Controls | FedRAMP Adds | Key FedRAMP Impact |
|---|---|---|---|
| GOV | 9 | +3 | SSP, login banners, rules of behavior |
| RSK | 8 | +2 | FIPS 199, ATO process |
| HRS | 7 | +3 | Position sensitivity screening, 3rd party personnel, transfers |
| AAM | 6 | +2 | Media transport/access controls |
| IAM | 13 | +5 | Session mgmt, SoD, info flow, wireless, NIST 800-63B |
| CRY | 5 | +1 | FIPS 140-2/3 validation requirement |
| PHY | 4 | — | Enhanced 800-53 enhancements in mappings |
| OPS | 8 | +3 | FedRAMP scan cadence, patch SLAs, software restrictions |
| NET | 7 | +1 | Authorization boundary documentation |
| SDL | 8 | +2 | FedRAMP pen test guidance, developer training |
| CHM | 6 | — | Deeper 800-53 enhancements |
| LOG | 6 | +2 | FedRAMP AU-2 event list, retention requirements |
| INC | 6 | +2 | US-CERT 1hr reporting, IR training |
| BCP | 6 | +2 | Alternate sites, contingency training |
| VND | 5 | +1 | Supply chain risk management (800-161) |
| PRI | 8 | — | Privacy controls carry forward |
| DGV | 3 | — | Data governance carries forward |
| CMP | 4 | +2 | POA&M management, FedRAMP ConMon |
| EDP | 3 | — | FIPS encryption requirement added |

---

## Getting Started with FedRAMP

### If You're Starting from Scratch

1. Import the commercial OpenCCF first and get your house in order (SOC 2, ISO 27001)
2. Layer the FedRAMP edition on top — the `fedramp_delta` field shows you exactly what's new
3. Use `fedramp-parameters.json` to configure your systems to FedRAMP-specified values
4. Begin SSP documentation against the FedRAMP SSP template

### If You Already Have FedRAMP Moderate

The jump from Moderate to High adds ~50 additional control enhancements in NIST 800-53. The biggest operational impacts are:
- Tighter patching SLAs
- More aggressive session management
- Supply chain controls
- Alternate processing site requirements
- Enhanced audit and monitoring depth

### Key FedRAMP Resources

- [FedRAMP Document Library](https://www.fedramp.gov/documents/)
- [FedRAMP Rev 5 Baselines](https://www.fedramp.gov/baselines/)
- [FedRAMP SSP Template](https://www.fedramp.gov/documents/)
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-63B Digital Identity](https://pages.nist.gov/800-63-3/sp800-63b.html)

---

## Relationship to Commercial OpenCCF

```
openccf/
├── openccf.json              ← Commercial baseline (103 controls, 10 frameworks)
├── openccf.csv
├── generate_ccf.py
├── README.md
└── fedramp/
    ├── openccf-fedramp.json  ← FedRAMP edition (122 controls, 11 frameworks)
    ├── openccf-fedramp.csv
    ├── fedramp-parameters.json  ← ODPs and additional requirements
    ├── generate_ccf_fedramp.py
    └── README.md             ← This file
```

The FedRAMP edition is a **superset** of the commercial edition. Every commercial control exists here (with `fedramp_delta: false`), plus the FedRAMP-specific additions (`fedramp_delta: true`).

---

## Contributing

FedRAMP-specific contributions are especially welcome:
- **ODP corrections** — if FedRAMP has updated parameter values
- **3PAO testing experience** — what auditors actually test vs. what the docs say
- **Moderate baseline variant** — a trimmed version for FedRAMP Moderate
- **StateRAMP / TX-RAMP mappings** — state-level authorization programs
- **DoD IL4/IL5 extensions** — for DoD-specific requirements

---

## License

Apache 2.0

---

## Disclaimer

This framework is a community resource and does not constitute official FedRAMP guidance. Always refer to the [FedRAMP PMO](https://www.fedramp.gov/) for authoritative requirements. Your 3PAO will be the final arbiter of control adequacy.
