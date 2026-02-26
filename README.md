# Open Common Controls Framework (OpenCCF)

**A vendor-neutral, open-source Common Controls Framework that rationalizes commercial and government compliance requirements into unified control sets with cross-framework mappings.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## What This Repo Contains

| Edition | Path | Controls | Use Case |
|--------|------|----------|----------|
| **Commercial** | [`commercial/`](commercial/) | 103 | SOC 2, ISO 27001, PCI DSS, HIPAA, GDPR, NIST CSF, and other commercial SaaS frameworks |
| **FedRAMP / Government** | [`fedramp/`](fedramp/) | 122 | Everything in Commercial + FedRAMP High (NIST 800-53 Rev 5 High baseline) |

Both editions ship as **JSON** (for GRC tools and APIs) and **CSV** (for spreadsheets). The FedRAMP edition extends the commercial baseline with 31 additional controls and FedRAMP-specific parameters.

---

## Quick Links

- **[Commercial OpenCCF](commercial/README.md)** — 10 frameworks, 1,161 mappings. Start here if you’re building a compliance program for enterprise SaaS.
- **[FedRAMP / Government OpenCCF](fedramp/README.md)** — 11 frameworks (adds FedRAMP), 1,707 mappings, Organization-Defined Parameters (ODPs). Use this if you’re pursuing FedRAMP High authorization.

---

## Repository Structure

```
.
├── README.md           # This file
├── LICENSE             # Apache 2.0
├── CONTRIBUTING.md     # How to contribute
├── commercial/         # Commercial edition
│   ├── README.md
│   ├── openccf.json    # Full CCF (source: generate_ccf.py)
│   ├── openccf.csv     # Flat CSV export
│   └── generate_ccf.py # Generator script
└── fedramp/            # FedRAMP / Government edition
    ├── README.md
    ├── openccf-fedramp.json
    ├── openccf-fedramp.csv
    ├── fedramp-parameters.json  # FedRAMP ODPs and requirements
    └── generate_ccf_fedramp.py   # Generator script
```

---

## License

This project is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for the full text. Use it, fork it, and build on it; attribution is appreciated but not required.

---

## Contributing

Contributions are welcome — mapping corrections, new framework mappings, control refinements, and tooling. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
