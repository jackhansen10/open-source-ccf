# OpenCCF — Open Common Controls Framework

**A vendor-neutral, open-source Common Controls Framework that rationalizes the most common compliance requirements for commercial SaaS companies into a single, unified control set.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)]()

---

## Why OpenCCF Exists

If you've ever built a compliance program for a SaaS company, you know the pain: SOC 2 wants one thing, ISO 27001 says almost the same thing differently, NIST 800-53 goes five layers deeper, and PCI DSS has its own vocabulary for controls you've already implemented. You end up with duplicate evidence, redundant audits, and a GRC tool full of controls that are 80% overlapping but mapped 1:1 to each framework.

OpenCCF solves this by defining a **single set of controls** that map across all major commercial compliance frameworks. One control, tested once, evidenced once, mapped everywhere.

### What OpenCCF Is

- **103 unified controls** across **19 domains**
- **1,161 cross-framework mappings** to **10 compliance frameworks**
- Ready for import into GRC platforms (JSON + CSV)
- A starting point you customize to your environment — not a rigid standard

### What OpenCCF Is Not

- Not a replacement for reading the actual framework requirements
- Not legal advice or a guarantee of compliance
- Not an evidence mapping (that's environment-specific — see [Extending OpenCCF](#extending-openccf))

---

## Frameworks Mapped

| Framework | Version | Publisher | Why It's Here |
|---|---|---|---|
| **SOC 2 TSC** | 2017 (2022 updates) | AICPA | Table stakes for any SaaS sale |
| **ISO 27001** | 2022 (Annex A) | ISO/IEC | Required for enterprise and international deals |
| **ISO 27017** | 2015 | ISO/IEC | Cloud-specific security — small delta from 27001 |
| **ISO 27018** | 2019 | ISO/IEC | PII in public cloud — increasingly asked for |
| **NIST CSF** | 2.0 | NIST | Risk framework lingua franca |
| **NIST 800-53** | Rev 5 | NIST | Underlies FedRAMP; referenced in enterprise questionnaires |
| **PCI DSS** | 4.0 | PCI SSC | If you touch payment data |
| **HIPAA Security Rule** | 45 CFR 164 | HHS | Healthcare vertical |
| **GDPR** | Regulation (EU) 2016/679 | EU | EU customer data |
| **CCPA / CPRA** | Cal. Civ. Code §1798 | State of California | US privacy baseline |

---

## Control Taxonomy

### Domain Structure

Controls are organized into 19 domains with a three-letter prefix:

| Domain ID | Domain Name | Controls | Focus Area |
|---|---|---|---|
| `GOV` | Governance | 6 | Policies, oversight, accountability |
| `RSK` | Risk Management | 6 | Risk identification, assessment, treatment |
| `HRS` | Human Resources Security | 5 | Hiring, training, termination |
| `AAM` | Asset Management | 4 | Inventory, classification, disposal |
| `IAM` | Identity & Access Management | 9 | Authentication, authorization, access lifecycle |
| `CRY` | Cryptography | 5 | Encryption, key management |
| `PHY` | Physical Security | 4 | Facility access, environmental controls |
| `OPS` | Operations Security | 7 | Hardening, patching, vulnerability management |
| `NET` | Network Security | 6 | Segmentation, firewalls, IDS/IPS |
| `SDL` | Secure Development Lifecycle | 7 | SDLC, code review, security testing |
| `CHM` | Change Management | 6 | Change control, configuration management |
| `LOG` | Logging & Monitoring | 5 | Audit logging, SIEM, alerting |
| `INC` | Incident Management | 5 | Detection, response, notification |
| `BCP` | Business Continuity & DR | 4 | BCP, DRP, high availability |
| `VND` | Vendor Management | 4 | Third-party risk, contracts, monitoring |
| `PRI` | Privacy | 10 | GDPR/CCPA compliance, data subject rights |
| `DGV` | Data Governance | 3 | Data integrity, DLP, anonymization |
| `CMP` | Compliance & Audit | 4 | Internal/external audit, continuous monitoring |
| `EDP` | Endpoint Security | 3 | Device management, encryption, mobile |

### Control ID Format

```
CCF-{DOMAIN}-{##}
```

Example: `CCF-IAM-03` = Identity & Access Management, Control 03 (Multi-Factor Authentication)

### Control Attributes

Each control includes:

| Attribute | Description |
|---|---|
| `id` | Unique control identifier (e.g., `CCF-GOV-01`) |
| `title` | Short, descriptive control name |
| `description` | Full control statement — what must be done |
| `objective` | Why the control exists — what it achieves |
| `control_type` | `Administrative`, `Technical`, `Operational`, or `Physical` |
| `frequency` | How often the control should be executed or reviewed |
| `mappings` | Framework-specific control references |

---

## File Formats

### `openccf.json` (Primary)

Structured, nested JSON for programmatic consumption and GRC tool import.

```json
{
  "metadata": { ... },
  "domains": [
    {
      "id": "IAM",
      "name": "Identity and Access Management",
      "controls": [
        {
          "id": "CCF-IAM-03",
          "title": "Multi-Factor Authentication",
          "description": "...",
          "objective": "...",
          "control_type": "Technical",
          "frequency": "Continuous enforcement; annual MFA coverage review",
          "mappings": {
            "soc2": ["CC6.1", "CC6.6"],
            "iso27001": ["A.8.5"],
            "nist_800_53": ["IA-2(1)", "IA-2(2)"],
            "pci_dss": ["8.4.1", "8.4.2", "8.4.3"],
            ...
          }
        }
      ]
    }
  ]
}
```

### `openccf.csv` (Flat)

One row per control, semicolon-delimited mappings per framework column. Import directly into spreadsheets or GRC tools.

---

## Getting Started

### 1. Import into Your GRC Tool

Most GRC platforms (Vanta, Drata, Anecdotes, AuditBoard, ServiceNow GRC, Hyperproof) support CSV or JSON import of custom control frameworks. Import `openccf.json` or `openccf.csv` as your base framework.

### 2. Tailor to Your Environment

Not every control applies to every company. Scope the framework to your context:

- **No office? No data center?** → Descope `PHY` or mark as inherited from cloud provider
- **No payment processing?** → Ignore PCI DSS mappings
- **No healthcare customers?** → Ignore HIPAA mappings
- **B2B only, no consumer PII?** → Lighten `PRI` domain scope

### 3. Add Evidence Mappings

OpenCCF intentionally does **not** include evidence mappings because they're entirely dependent on your tech stack. You'll want to add:

| Column | Example |
|---|---|
| `evidence_source` | AWS Config, Okta, GitHub, Jira |
| `evidence_description` | "Screenshot of MFA enforcement policy in Okta" |
| `evidence_frequency` | Continuous / Quarterly / Annual |
| `automation_status` | Automated / Semi-Automated / Manual |
| `control_owner` | Team or individual responsible |

### 4. Map to Your Org

Assign every control an owner. No owner = no accountability = audit finding.

---

## Extending OpenCCF

### Adding a Framework

To add a new framework (e.g., FedRAMP, SOX ITGC, TISAX):

1. Add the framework metadata to `metadata.frameworks`
2. Add a new key to each control's `mappings` object
3. Populate the mapping references
4. Submit a PR with your additions

### Adding Controls

If your organization needs controls not covered by OpenCCF (e.g., AI/ML governance, specific industry requirements):

1. Follow the `CCF-{DOMAIN}-{##}` naming convention
2. Include all required attributes
3. Map to relevant frameworks
4. Submit a PR

---

## Design Decisions

A few decisions worth documenting:

**Why ~100 controls and not 400?** Because 400-control frameworks don't get operationalized. They get shelf-ware'd. OpenCCF targets the right granularity: specific enough to be auditable, general enough to be implementable across different tech stacks.

**Why no evidence mappings?** Evidence is environment-specific. Your "MFA is enforced" evidence comes from Okta, or Azure AD, or Google Workspace — and the artifact looks different in each. Baking in evidence mappings would either be too generic to be useful or too specific to be portable.

**Why both JSON and CSV?** JSON is the right format for programmatic consumption, API integration, and GRC tool import. CSV is the right format for humans who want to open it in Excel and start working. Both are generated from the same source of truth.

**Why these 10 frameworks?** These cover the vast majority of commercial SaaS compliance requirements globally. SOC 2 + ISO 27001 get you through 90% of enterprise sales. Add PCI/HIPAA for regulated verticals. Add NIST for government-adjacent. Add GDPR/CCPA for privacy. This is the stack most scaling SaaS companies actually need.

---

## Mapping Accuracy

Framework mappings represent the primary relevant requirements. In practice:

- Some framework requirements map to multiple CCF controls (many-to-many)
- Some CCF controls have stronger alignment to certain frameworks than others
- Framework requirements may have additional sub-requirements not fully captured in a single mapping
- Mappings should be validated against the specific version of each framework you're being audited against

**Always verify mappings against the actual framework text for your audit scope.**

---

## Contributing

Contributions are welcome. Particularly valuable:

1. **Mapping corrections** — if you spot a mapping that's wrong or missing, please file an issue or PR
2. **New framework mappings** — add coverage for frameworks not yet included
3. **Control refinements** — improve control descriptions based on real audit experience
4. **Tooling** — scripts to convert OpenCCF into specific GRC platform formats

### Contribution Guidelines

- Keep control descriptions implementation-agnostic (no vendor-specific language)
- Include framework section/article references, not just descriptions
- One PR per logical change (don't bundle framework additions with control rewrites)
- Test that JSON remains valid after changes

---

## License

Apache 2.0 — use it, fork it, build on it. Attribution appreciated but not required.

---

## Acknowledgments

Built by compliance practitioners who got tired of mapping the same control to five frameworks in five different spreadsheets.

If this saves you even one week of audit prep, it was worth it.
