#!/usr/bin/env python3
"""
Open Common Controls Framework (OpenCCF) Generator
Generates the full CCF with cross-framework mappings in JSON and CSV formats.
"""

import json
import csv
import os
from datetime import date

# =============================================================================
# METADATA
# =============================================================================
METADATA = {
    "name": "Open Common Controls Framework (OpenCCF)",
    "version": "1.0.0",
    "license": "Apache-2.0",
    "last_updated": date.today().isoformat(),
    "repository": "https://github.com/YOUR_ORG/openccf",
    "description": (
        "A vendor-neutral, open-source Common Controls Framework that unifies "
        "the most common compliance requirements for commercial SaaS companies "
        "into a single, rationalized control set with cross-framework mappings."
    ),
    "frameworks": {
        "soc2": {
            "name": "SOC 2 Trust Services Criteria",
            "version": "2017 (with 2022 points of focus updates)",
            "publisher": "AICPA",
            "prefix_guide": "CC=Common Criteria, A1=Availability, C1=Confidentiality, PI1=Processing Integrity, P=Privacy"
        },
        "iso27001": {
            "name": "ISO/IEC 27001:2022 Annex A",
            "version": "2022",
            "publisher": "ISO/IEC",
            "prefix_guide": "A.5=Organizational, A.6=People, A.7=Physical, A.8=Technological"
        },
        "iso27017": {
            "name": "ISO/IEC 27017:2015",
            "version": "2015",
            "publisher": "ISO/IEC",
            "prefix_guide": "Cloud-specific security controls extending ISO 27002"
        },
        "iso27018": {
            "name": "ISO/IEC 27018:2019",
            "version": "2019",
            "publisher": "ISO/IEC",
            "prefix_guide": "PII protection in public cloud"
        },
        "nist_csf": {
            "name": "NIST Cybersecurity Framework",
            "version": "2.0",
            "publisher": "NIST",
            "prefix_guide": "GV=Govern, ID=Identify, PR=Protect, DE=Detect, RS=Respond, RC=Recover"
        },
        "nist_800_53": {
            "name": "NIST SP 800-53",
            "version": "Revision 5",
            "publisher": "NIST",
            "prefix_guide": "Control families: AC, AT, AU, CA, CM, CP, IA, IR, MA, MP, PE, PL, PM, PS, PT, RA, SA, SC, SI, SR"
        },
        "pci_dss": {
            "name": "PCI DSS",
            "version": "4.0",
            "publisher": "PCI SSC",
            "prefix_guide": "Requirements 1-12"
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "version": "45 CFR Part 164",
            "publisher": "HHS",
            "prefix_guide": "§164.308=Admin, §164.310=Physical, §164.312=Technical, §164.314=Organizational, §164.316=Policies"
        },
        "gdpr": {
            "name": "General Data Protection Regulation",
            "version": "Regulation (EU) 2016/679",
            "publisher": "European Parliament",
            "prefix_guide": "Articles 5-49"
        },
        "ccpa": {
            "name": "CCPA / CPRA",
            "version": "California Civil Code §1798.100-199.100",
            "publisher": "State of California",
            "prefix_guide": "§1798.xxx sections"
        }
    }
}

# =============================================================================
# DOMAIN AND CONTROL DEFINITIONS
# =============================================================================

DOMAINS = [
    # =========================================================================
    # DOMAIN: GOV - Governance
    # =========================================================================
    {
        "id": "GOV",
        "name": "Governance",
        "description": "Establishes the organizational structures, policies, and oversight mechanisms that direct and govern the information security program.",
        "controls": [
            {
                "id": "CCF-GOV-01",
                "title": "Information Security Policy",
                "description": "The organization establishes, approves, and communicates a formal information security policy that defines the organization's commitment to security, assigns accountability, and sets the strategic direction for the security program. The policy is reviewed at least annually and updated as needed.",
                "objective": "Ensure a management-approved security policy exists, is communicated, and remains current.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon significant change",
                "mappings": {
                    "soc2": ["CC1.1", "CC1.2"],
                    "iso27001": ["A.5.1"],
                    "iso27017": ["5.1.1"],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01", "GV.PO-02"],
                    "nist_800_53": ["PL-1", "PM-1"],
                    "pci_dss": ["12.1", "12.1.1"],
                    "hipaa": ["§164.316(a)"],
                    "gdpr": ["Art. 24", "Art. 32"],
                    "ccpa": ["§1798.100(e)"]
                }
            },
            {
                "id": "CCF-GOV-02",
                "title": "Security Roles and Responsibilities",
                "description": "The organization defines, documents, and communicates information security roles and responsibilities for all personnel, including executive leadership, security team, IT operations, engineering, and general workforce. Accountability for control ownership is clearly assigned.",
                "objective": "Ensure clear ownership and accountability for security responsibilities across the organization.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon organizational change",
                "mappings": {
                    "soc2": ["CC1.2", "CC1.3"],
                    "iso27001": ["A.5.2", "A.5.4"],
                    "iso27017": ["6.1.1"],
                    "iso27018": [],
                    "nist_csf": ["GV.RR-01", "GV.RR-02"],
                    "nist_800_53": ["PL-1", "PM-2", "PM-13"],
                    "pci_dss": ["12.1.2", "12.4"],
                    "hipaa": ["§164.308(a)(2)"],
                    "gdpr": ["Art. 24", "Art. 37"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-03",
                "title": "Executive Oversight and Reporting",
                "description": "Senior leadership and/or the board of directors provide oversight of the information security program through regular reporting on security posture, risk status, compliance status, and material security events. Security metrics are reported to leadership at least quarterly.",
                "objective": "Ensure executive visibility into and accountability for the security program.",
                "control_type": "Administrative",
                "frequency": "Quarterly reporting; annual program review",
                "mappings": {
                    "soc2": ["CC1.2", "CC4.1", "CC4.2"],
                    "iso27001": ["A.5.1", "A.5.4"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-01", "GV.OV-02", "GV.OV-03"],
                    "nist_800_53": ["PM-1", "PM-6"],
                    "pci_dss": ["12.4", "12.4.1"],
                    "hipaa": ["§164.308(a)(2)"],
                    "gdpr": ["Art. 24"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-04",
                "title": "Acceptable Use Policy",
                "description": "The organization defines and communicates an acceptable use policy that governs the appropriate use of organizational assets, systems, and data. The policy covers topics including personal use, prohibited activities, and consequences for violations.",
                "objective": "Establish clear expectations for appropriate use of organizational resources.",
                "control_type": "Administrative",
                "frequency": "Annual review; acknowledgment at hire and annually",
                "mappings": {
                    "soc2": ["CC1.1", "CC1.4"],
                    "iso27001": ["A.5.10"],
                    "iso27017": ["8.1.3"],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PL-4"],
                    "pci_dss": ["12.3"],
                    "hipaa": ["§164.310(b)", "§164.312(a)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-05",
                "title": "Code of Conduct and Ethics",
                "description": "The organization maintains a code of conduct that establishes ethical expectations and behavioral standards for all personnel. Adherence is required as a condition of employment/engagement and is reinforced through regular communication.",
                "objective": "Set ethical expectations and create accountability for organizational conduct.",
                "control_type": "Administrative",
                "frequency": "Annual acknowledgment; review upon significant change",
                "mappings": {
                    "soc2": ["CC1.1", "CC1.4", "CC1.5"],
                    "iso27001": ["A.5.4", "A.6.2"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PL-4", "PS-8"],
                    "pci_dss": ["12.6.3.2"],
                    "hipaa": ["§164.308(a)(1)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-06",
                "title": "Regulatory and Contractual Compliance Management",
                "description": "The organization identifies, tracks, and maintains compliance with applicable legal, regulatory, and contractual requirements. A compliance register is maintained and reviewed regularly to ensure obligations are met and changes are addressed.",
                "objective": "Ensure the organization meets all applicable external obligations.",
                "control_type": "Administrative",
                "frequency": "Continuous; formal review quarterly",
                "mappings": {
                    "soc2": ["CC2.3", "CC3.1"],
                    "iso27001": ["A.5.31", "A.5.32", "A.5.33", "A.5.34"],
                    "iso27017": [],
                    "iso27018": ["A.18.1.4"],
                    "nist_csf": ["GV.OC-02", "GV.OC-03"],
                    "nist_800_53": ["CA-2", "PM-10"],
                    "pci_dss": ["12.1.1", "12.4.2"],
                    "hipaa": ["§164.316(b)(2)(iii)"],
                    "gdpr": ["Art. 24", "Art. 5(2)"],
                    "ccpa": ["§1798.185"]
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: RSK - Risk Management
    # =========================================================================
    {
        "id": "RSK",
        "name": "Risk Management",
        "description": "Defines the processes for identifying, analyzing, evaluating, treating, and monitoring information security risks to the organization.",
        "controls": [
            {
                "id": "CCF-RSK-01",
                "title": "Risk Management Program",
                "description": "The organization establishes and maintains a formal risk management program that defines the methodology, scope, frequency, and criteria for information security risk assessments. The program is aligned with organizational objectives and risk appetite.",
                "objective": "Provide a systematic approach to identifying and managing information security risks.",
                "control_type": "Administrative",
                "frequency": "Annual program review; continuous risk identification",
                "mappings": {
                    "soc2": ["CC3.1", "CC3.2"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.RM-01", "GV.RM-02", "ID.RA-01"],
                    "nist_800_53": ["RA-1", "RA-2", "PM-9"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(2)", "Art. 35"],
                    "ccpa": ["§1798.100(e)"]
                }
            },
            {
                "id": "CCF-RSK-02",
                "title": "Risk Assessment Execution",
                "description": "The organization performs comprehensive risk assessments at least annually and upon significant changes to the environment, business, or threat landscape. Assessments identify threats, vulnerabilities, likelihood, and impact to organizational assets and operations.",
                "objective": "Identify and evaluate current security risks based on the threat environment.",
                "control_type": "Administrative",
                "frequency": "Annual; upon significant change; new projects/systems",
                "mappings": {
                    "soc2": ["CC3.2", "CC3.3"],
                    "iso27001": ["A.5.8", "A.8.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-01", "ID.RA-02", "ID.RA-03"],
                    "nist_800_53": ["RA-3", "RA-5"],
                    "pci_dss": ["6.3.1", "12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(2)", "Art. 35(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-03",
                "title": "Risk Treatment and Mitigation",
                "description": "The organization defines and implements risk treatment plans for identified risks. Treatment options include mitigation, transfer, acceptance, and avoidance. Risk owners are assigned and accountable for the implementation and effectiveness of treatment plans.",
                "objective": "Ensure identified risks are addressed through appropriate treatment actions.",
                "control_type": "Administrative",
                "frequency": "Ongoing; reviewed quarterly",
                "mappings": {
                    "soc2": ["CC3.3", "CC3.4", "CC5.1"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-05", "ID.RA-06"],
                    "nist_800_53": ["RA-7", "PM-4"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(B)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-04",
                "title": "Risk Register Maintenance",
                "description": "The organization maintains a risk register that documents identified risks, risk ratings, risk owners, treatment decisions, and residual risk. The register is reviewed and updated at least quarterly and upon identification of new material risks.",
                "objective": "Maintain a centralized, current view of the organization's risk posture.",
                "control_type": "Administrative",
                "frequency": "Quarterly update; continuous intake",
                "mappings": {
                    "soc2": ["CC3.2", "CC3.4", "CC4.1"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-04", "GV.RM-05"],
                    "nist_800_53": ["PM-4", "RA-3"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(2)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-05",
                "title": "Risk Acceptance",
                "description": "The organization maintains a formal risk acceptance process requiring documented approval from authorized management for risks that exceed tolerance levels or will not be treated within defined timeframes. Accepted risks are periodically re-evaluated.",
                "objective": "Ensure residual risks are consciously accepted by accountable individuals.",
                "control_type": "Administrative",
                "frequency": "Per occurrence; annual re-evaluation of accepted risks",
                "mappings": {
                    "soc2": ["CC3.4", "CC5.3"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.RM-06", "GV.RM-07"],
                    "nist_800_53": ["PM-9", "CA-5"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(B)"],
                    "gdpr": ["Art. 32"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-06",
                "title": "Threat Intelligence",
                "description": "The organization collects, analyzes, and acts upon threat intelligence relevant to its industry, technology stack, and threat profile. Threat information is used to inform risk assessments, security monitoring, and vulnerability management activities.",
                "objective": "Maintain awareness of the current threat landscape to proactively manage risk.",
                "control_type": "Operational",
                "frequency": "Continuous",
                "mappings": {
                    "soc2": ["CC3.1", "CC7.2"],
                    "iso27001": ["A.5.7"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-02"],
                    "nist_800_53": ["PM-16", "RA-3", "SI-5"],
                    "pci_dss": ["6.3.1"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: HRS - Human Resources Security
    # =========================================================================
    {
        "id": "HRS",
        "name": "Human Resources Security",
        "description": "Controls ensuring security considerations are integrated into employment lifecycle processes from hiring through termination.",
        "controls": [
            {
                "id": "CCF-HRS-01",
                "title": "Background Screening",
                "description": "The organization conducts background checks on personnel prior to granting access to organizational systems and data. The scope of screening is commensurate with the role's level of access and applicable legal requirements.",
                "objective": "Verify the trustworthiness and suitability of personnel before granting access.",
                "control_type": "Administrative",
                "frequency": "Prior to employment/engagement; periodic re-screening for sensitive roles",
                "mappings": {
                    "soc2": ["CC1.4"],
                    "iso27001": ["A.6.1"],
                    "iso27017": [],
                    "iso27018": ["A.11.4"],
                    "nist_csf": ["PR.IP-11"],
                    "nist_800_53": ["PS-3"],
                    "pci_dss": ["12.7", "12.7.1"],
                    "hipaa": ["§164.308(a)(3)(ii)(B)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-02",
                "title": "Confidentiality and Security Agreements",
                "description": "Personnel and relevant third parties are required to acknowledge and sign confidentiality (NDA) and security obligations as a condition of access to organizational systems and data. Agreements cover data handling, acceptable use, and post-employment obligations.",
                "objective": "Establish binding security and confidentiality obligations for all personnel.",
                "control_type": "Administrative",
                "frequency": "At hire/engagement; upon material policy change",
                "mappings": {
                    "soc2": ["CC1.4", "CC1.5"],
                    "iso27001": ["A.6.2", "A.5.14"],
                    "iso27017": ["6.1.2"],
                    "iso27018": ["A.6.1.2"],
                    "nist_csf": ["PR.IP-11"],
                    "nist_800_53": ["PS-6", "PL-4"],
                    "pci_dss": ["12.8.2"],
                    "hipaa": ["§164.308(a)(4)(ii)(B)", "§164.314(a)(2)"],
                    "gdpr": ["Art. 28(3)", "Art. 38(5)"],
                    "ccpa": ["§1798.140(w)"]
                }
            },
            {
                "id": "CCF-HRS-03",
                "title": "Security Awareness Training",
                "description": "The organization provides security awareness training to all personnel upon hire and at least annually thereafter. Training covers the organization's security policies, common threats (phishing, social engineering), data handling requirements, and incident reporting procedures. Role-specific training is provided for personnel in security-sensitive functions.",
                "objective": "Ensure all personnel understand their security responsibilities and can identify common threats.",
                "control_type": "Administrative",
                "frequency": "At onboarding; annual refresher; ad hoc for emerging threats",
                "mappings": {
                    "soc2": ["CC1.4", "CC2.2"],
                    "iso27001": ["A.6.3"],
                    "iso27017": ["7.2.2"],
                    "iso27018": ["A.7.2.2"],
                    "nist_csf": ["PR.AT-01", "PR.AT-02"],
                    "nist_800_53": ["AT-2", "AT-3", "AT-4"],
                    "pci_dss": ["12.6", "12.6.1", "12.6.2"],
                    "hipaa": ["§164.308(a)(5)(i)", "§164.308(a)(5)(ii)(A)"],
                    "gdpr": ["Art. 39(1)(b)", "Art. 47(2)(n)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-04",
                "title": "Disciplinary Process",
                "description": "The organization maintains a formal disciplinary process for personnel who violate security policies. The process includes escalation procedures, investigation steps, and consequences proportionate to the severity and nature of the violation.",
                "objective": "Deter security policy violations and ensure consistent enforcement.",
                "control_type": "Administrative",
                "frequency": "Per occurrence; annual policy review",
                "mappings": {
                    "soc2": ["CC1.5"],
                    "iso27001": ["A.6.4"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": [],
                    "nist_800_53": ["PS-8"],
                    "pci_dss": ["12.6.3.2"],
                    "hipaa": ["§164.308(a)(1)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-05",
                "title": "Personnel Offboarding and Termination",
                "description": "The organization implements a formal offboarding process that ensures timely revocation of access upon termination, resignation, or role change. The process includes return of assets, revocation of logical and physical access, and knowledge transfer where appropriate.",
                "objective": "Prevent unauthorized access by former or transitioning personnel.",
                "control_type": "Administrative",
                "frequency": "Per occurrence (same day for involuntary; within 24 hours for voluntary)",
                "mappings": {
                    "soc2": ["CC6.2", "CC6.5"],
                    "iso27001": ["A.6.5"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["PS-4", "PS-5"],
                    "pci_dss": ["8.2.6", "12.7"],
                    "hipaa": ["§164.308(a)(3)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: AAM - Asset Management
    # =========================================================================
    {
        "id": "AAM",
        "name": "Asset Management",
        "description": "Controls for the identification, classification, and management of organizational assets including hardware, software, data, and cloud resources.",
        "controls": [
            {
                "id": "CCF-AAM-01",
                "title": "Asset Inventory",
                "description": "The organization maintains a complete and accurate inventory of information assets including hardware, software, cloud resources, and data stores. Asset ownership is assigned and the inventory is updated continuously or reviewed at least quarterly.",
                "objective": "Maintain visibility into all organizational assets to enable effective security management.",
                "control_type": "Operational",
                "frequency": "Continuous (automated); quarterly manual review",
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.5.9", "A.5.10", "A.5.11"],
                    "iso27017": ["8.1.1"],
                    "iso27018": [],
                    "nist_csf": ["ID.AM-01", "ID.AM-02"],
                    "nist_800_53": ["CM-8", "PM-5"],
                    "pci_dss": ["9.5.1", "12.5.1"],
                    "hipaa": ["§164.310(d)(1)"],
                    "gdpr": ["Art. 30"],
                    "ccpa": ["§1798.100(a)"]
                }
            },
            {
                "id": "CCF-AAM-02",
                "title": "Data Classification",
                "description": "The organization implements a data classification scheme that categorizes data based on sensitivity, regulatory requirements, and business value. Classification levels (e.g., Public, Internal, Confidential, Restricted) drive data handling, storage, and transmission requirements.",
                "objective": "Enable appropriate protection of data based on its sensitivity and value.",
                "control_type": "Administrative",
                "frequency": "At data creation; reviewed annually; upon regulatory change",
                "mappings": {
                    "soc2": ["CC6.1", "C1.1"],
                    "iso27001": ["A.5.12", "A.5.13"],
                    "iso27017": ["8.2.2"],
                    "iso27018": ["A.10.1"],
                    "nist_csf": ["ID.AM-05"],
                    "nist_800_53": ["RA-2", "SC-16"],
                    "pci_dss": ["9.4.1"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 9", "Art. 10"],
                    "ccpa": ["§1798.140(v)"]
                }
            },
            {
                "id": "CCF-AAM-03",
                "title": "Media and Asset Disposal",
                "description": "The organization implements procedures for the secure disposal and destruction of media and assets containing sensitive data. Disposal methods are commensurate with the data classification and include verification of destruction.",
                "objective": "Prevent unauthorized disclosure of data through improper asset disposal.",
                "control_type": "Operational",
                "frequency": "Per occurrence; annual process review",
                "mappings": {
                    "soc2": ["CC6.5"],
                    "iso27001": ["A.7.10", "A.7.14", "A.8.10"],
                    "iso27017": [],
                    "iso27018": ["A.9.4.2"],
                    "nist_csf": ["PR.DS-03"],
                    "nist_800_53": ["MP-6", "PE-16"],
                    "pci_dss": ["9.4.5", "9.4.6", "9.4.7"],
                    "hipaa": ["§164.310(d)(2)(i)", "§164.310(d)(2)(ii)"],
                    "gdpr": ["Art. 17"],
                    "ccpa": ["§1798.105"]
                }
            },
            {
                "id": "CCF-AAM-04",
                "title": "Cloud Resource Management",
                "description": "The organization maintains an inventory and governance process for cloud resources, including IaaS, PaaS, and SaaS services. Cloud resource provisioning follows approved architecture patterns and is subject to configuration management and tagging standards.",
                "objective": "Ensure cloud resources are inventoried, governed, and secured throughout their lifecycle.",
                "control_type": "Operational",
                "frequency": "Continuous (automated); monthly review",
                "mappings": {
                    "soc2": ["CC6.1", "CC7.1"],
                    "iso27001": ["A.5.23"],
                    "iso27017": ["CLD.6.3", "CLD.8.1"],
                    "iso27018": [],
                    "nist_csf": ["ID.AM-02"],
                    "nist_800_53": ["CM-8", "SA-9"],
                    "pci_dss": ["2.1.1", "11.2.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 28"],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: IAM - Identity and Access Management
    # =========================================================================
    {
        "id": "IAM",
        "name": "Identity and Access Management",
        "description": "Controls governing user identity lifecycle, authentication, authorization, and access management across organizational systems and data.",
        "controls": [
            {
                "id": "CCF-IAM-01",
                "title": "Access Control Policy",
                "description": "The organization establishes an access control policy based on the principles of least privilege and need-to-know. The policy defines access authorization requirements, role-based access control (RBAC) standards, and procedures for granting, modifying, and revoking access.",
                "objective": "Establish the foundational policy for controlling access to organizational resources.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon significant change",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.3"],
                    "iso27001": ["A.5.15", "A.8.3"],
                    "iso27017": ["9.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01"],
                    "nist_800_53": ["AC-1", "AC-2", "AC-3"],
                    "pci_dss": ["7.1", "7.2"],
                    "hipaa": ["§164.312(a)(1)", "§164.308(a)(4)(i)"],
                    "gdpr": ["Art. 25", "Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-02",
                "title": "User Provisioning and Deprovisioning",
                "description": "The organization implements a formal process for provisioning and deprovisioning user accounts. Provisioning requires documented authorization from appropriate management. Deprovisioning occurs promptly upon role change, transfer, or termination.",
                "objective": "Ensure access is granted only when authorized and removed when no longer needed.",
                "control_type": "Operational",
                "frequency": "Per occurrence; automated where possible",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.2"],
                    "iso27001": ["A.5.16", "A.5.18"],
                    "iso27017": ["9.2.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01", "PR.AA-05"],
                    "nist_800_53": ["AC-2"],
                    "pci_dss": ["7.1", "8.2.4", "8.2.5", "8.2.6"],
                    "hipaa": ["§164.308(a)(3)(ii)(A)", "§164.308(a)(3)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-03",
                "title": "Multi-Factor Authentication",
                "description": "The organization requires multi-factor authentication (MFA) for all access to production systems, remote access, administrative interfaces, cloud consoles, and customer-facing applications where supported. MFA methods conform to industry standards (e.g., TOTP, FIDO2, push notification).",
                "objective": "Reduce the risk of unauthorized access due to credential compromise.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual MFA coverage review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.5"],
                    "iso27017": ["9.4.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["IA-2(1)", "IA-2(2)"],
                    "pci_dss": ["8.4.1", "8.4.2", "8.4.3"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-04",
                "title": "Privileged Access Management",
                "description": "The organization restricts and monitors privileged (administrative) access to information systems. Privileged access is granted based on demonstrated need, uses separate accounts from standard user accounts, and is subject to enhanced logging and periodic review.",
                "objective": "Minimize the attack surface from administrative access and ensure accountability.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; quarterly review of privileged accounts",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.3"],
                    "iso27001": ["A.8.2", "A.8.18"],
                    "iso27017": ["9.2.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["AC-6(5)", "AC-6(7)", "AC-6(10)"],
                    "pci_dss": ["7.2.1", "8.6.1"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-05",
                "title": "Access Reviews",
                "description": "The organization conducts periodic access reviews to validate that user access rights remain appropriate and aligned with job responsibilities. Reviews cover both standard and privileged accounts, including third-party access. Inappropriate access is remediated promptly.",
                "objective": "Detect and remediate access drift, orphaned accounts, and excessive permissions.",
                "control_type": "Operational",
                "frequency": "Quarterly for privileged access; semi-annually for standard access",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.2", "CC6.3"],
                    "iso27001": ["A.5.18", "A.8.2"],
                    "iso27017": ["9.2.5"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["AC-2(3)", "AC-6(7)"],
                    "pci_dss": ["7.2.4", "7.2.5"],
                    "hipaa": ["§164.308(a)(4)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-06",
                "title": "Password and Credential Management",
                "description": "The organization enforces password and credential management standards including minimum complexity requirements, expiration policies (where applicable), and prohibition of credential sharing. Credentials are stored using secure hashing algorithms and never in plaintext.",
                "objective": "Ensure authentication credentials are strong, unique, and securely managed.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement",
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.5.17", "A.8.5"],
                    "iso27017": ["9.4.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["IA-5"],
                    "pci_dss": ["8.3.1", "8.3.4", "8.3.6", "8.3.7"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-07",
                "title": "Service Account and API Key Management",
                "description": "The organization manages service accounts, API keys, and machine credentials through a formal lifecycle process. Service accounts are inventoried, assigned owners, granted minimum necessary permissions, and subject to credential rotation. Shared or embedded credentials are prohibited.",
                "objective": "Prevent unauthorized access through unmanaged non-human identities.",
                "control_type": "Technical",
                "frequency": "Continuous; quarterly inventory review; rotation per policy",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.3"],
                    "iso27001": ["A.5.16", "A.5.18", "A.8.5"],
                    "iso27017": ["9.2.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01", "PR.AA-03"],
                    "nist_800_53": ["AC-2", "IA-4", "IA-5"],
                    "pci_dss": ["8.6.1", "8.6.2", "8.6.3"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-08",
                "title": "Single Sign-On and Centralized Authentication",
                "description": "The organization implements centralized authentication through a single sign-on (SSO) solution integrated with a corporate identity provider (IdP). Application access is federated through the IdP, enabling centralized policy enforcement and streamlined access lifecycle management.",
                "objective": "Centralize authentication to enable consistent policy enforcement and auditability.",
                "control_type": "Technical",
                "frequency": "Continuous; annual coverage review for SSO integration gaps",
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.8.5"],
                    "iso27017": ["9.4.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["IA-2", "IA-8"],
                    "pci_dss": ["7.2", "8.4"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-09",
                "title": "Remote Access Security",
                "description": "The organization controls remote access to organizational systems through authorized, encrypted channels (e.g., VPN, zero-trust network access). Remote access requires MFA and is logged. Access from unmanaged or non-compliant devices is restricted.",
                "objective": "Secure remote connectivity while maintaining visibility and control.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.1", "A.6.7"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["AC-17"],
                    "pci_dss": ["8.4.3", "12.3.1"],
                    "hipaa": ["§164.312(a)(1)", "§164.312(e)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: CRY - Cryptography
    # =========================================================================
    {
        "id": "CRY",
        "name": "Cryptography",
        "description": "Controls governing the use of cryptographic techniques and key management to protect data confidentiality and integrity.",
        "controls": [
            {
                "id": "CCF-CRY-01",
                "title": "Encryption Policy",
                "description": "The organization establishes a cryptographic policy that defines approved encryption standards, algorithms, key lengths, and use cases for data at rest, in transit, and in use. The policy prohibits the use of deprecated or weak cryptographic methods.",
                "objective": "Establish consistent cryptographic standards across the organization.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon cryptographic vulnerability disclosure",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1"],
                    "iso27018": ["A.10.1.2"],
                    "nist_csf": ["PR.DS-01", "PR.DS-02"],
                    "nist_800_53": ["SC-13"],
                    "pci_dss": ["3.6.1", "4.2.1"],
                    "hipaa": ["§164.312(a)(2)(iv)", "§164.312(e)(2)(ii)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": ["§1798.150(a)"]
                }
            },
            {
                "id": "CCF-CRY-02",
                "title": "Encryption at Rest",
                "description": "The organization encrypts sensitive data at rest using approved algorithms (e.g., AES-256) across all storage systems including databases, object storage, file systems, backups, and removable media. Encryption is enforced by default for all environments containing production or customer data.",
                "objective": "Protect stored data from unauthorized disclosure in the event of unauthorized access to storage systems.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual configuration review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7", "C1.1"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1"],
                    "iso27018": ["A.11.6"],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["SC-28"],
                    "pci_dss": ["3.5.1", "3.5.1.1"],
                    "hipaa": ["§164.312(a)(2)(iv)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": ["§1798.150(a)"]
                }
            },
            {
                "id": "CCF-CRY-03",
                "title": "Encryption in Transit",
                "description": "The organization encrypts data in transit using approved protocols (e.g., TLS 1.2+, SSH) for all internal and external communications. Unencrypted transmission of sensitive data is prohibited. Certificate validation is enforced and insecure protocol fallback is disabled.",
                "objective": "Protect data from interception or tampering during transmission.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual protocol review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7", "C1.1"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1", "13.1.1"],
                    "iso27018": ["A.13.1.1"],
                    "nist_csf": ["PR.DS-02"],
                    "nist_800_53": ["SC-8", "SC-23"],
                    "pci_dss": ["4.2.1", "4.2.1.1"],
                    "hipaa": ["§164.312(e)(1)", "§164.312(e)(2)(ii)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CRY-04",
                "title": "Cryptographic Key Management",
                "description": "The organization implements a key management program covering the full lifecycle of cryptographic keys: generation, distribution, storage, rotation, revocation, and destruction. Keys are generated using approved random number generators, stored in dedicated key management systems (KMS/HSM), and rotated per defined schedules.",
                "objective": "Ensure cryptographic keys are securely managed throughout their lifecycle.",
                "control_type": "Technical",
                "frequency": "Continuous; rotation per policy; annual key management review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.2"],
                    "iso27018": ["A.10.1.2"],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["SC-12"],
                    "pci_dss": ["3.6.1", "3.7.1", "3.7.2", "3.7.3", "3.7.4"],
                    "hipaa": ["§164.312(a)(2)(iv)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CRY-05",
                "title": "Certificate Management",
                "description": "The organization maintains an inventory of TLS/SSL and other digital certificates, monitors certificate expiration, and ensures timely renewal. Certificates are issued by trusted certificate authorities and use approved key lengths and algorithms.",
                "objective": "Prevent service disruptions and security exposures from expired or misconfigured certificates.",
                "control_type": "Operational",
                "frequency": "Continuous monitoring; automated renewal where possible",
                "mappings": {
                    "soc2": ["CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-02"],
                    "nist_800_53": ["SC-17"],
                    "pci_dss": ["4.2.1"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: PHY - Physical Security
    # =========================================================================
    {
        "id": "PHY",
        "name": "Physical Security",
        "description": "Controls protecting physical facilities, equipment, and infrastructure from unauthorized access, damage, and environmental threats.",
        "controls": [
            {
                "id": "CCF-PHY-01",
                "title": "Physical Access Controls",
                "description": "The organization restricts physical access to facilities, data centers, and sensitive areas to authorized personnel. Access control mechanisms include badge systems, biometric readers, and key management. Access is granted based on job role and revoked promptly upon role change or termination.",
                "objective": "Prevent unauthorized physical access to facilities containing information assets.",
                "control_type": "Physical",
                "frequency": "Continuous enforcement; quarterly access list review",
                "mappings": {
                    "soc2": ["CC6.4"],
                    "iso27001": ["A.7.1", "A.7.2", "A.7.3"],
                    "iso27017": ["11.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-02"],
                    "nist_800_53": ["PE-2", "PE-3", "PE-6"],
                    "pci_dss": ["9.2", "9.3"],
                    "hipaa": ["§164.310(a)(1)", "§164.310(a)(2)(ii)", "§164.310(a)(2)(iii)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-PHY-02",
                "title": "Visitor Management",
                "description": "The organization maintains a visitor management process that includes visitor registration, identification verification, escort requirements, and visitor log maintenance. Visitors are not permitted unescorted access to sensitive areas.",
                "objective": "Control and document visitor access to organizational facilities.",
                "control_type": "Physical",
                "frequency": "Per occurrence; monthly log review",
                "mappings": {
                    "soc2": ["CC6.4"],
                    "iso27001": ["A.7.2"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-02"],
                    "nist_800_53": ["PE-8"],
                    "pci_dss": ["9.3.1", "9.3.2", "9.3.3"],
                    "hipaa": ["§164.310(a)(2)(iii)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-PHY-03",
                "title": "Environmental Controls",
                "description": "The organization implements environmental protections for facilities housing critical systems including fire detection and suppression, climate controls (HVAC), water detection, and uninterruptible power supply (UPS). Environmental systems are monitored and tested regularly.",
                "objective": "Protect information systems from environmental threats and failures.",
                "control_type": "Physical",
                "frequency": "Continuous monitoring; semi-annual testing",
                "mappings": {
                    "soc2": ["A1.2"],
                    "iso27001": ["A.7.5", "A.7.8", "A.7.11", "A.7.12"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-03"],
                    "nist_800_53": ["PE-10", "PE-11", "PE-12", "PE-13", "PE-14", "PE-15"],
                    "pci_dss": ["9.1.1"],
                    "hipaa": ["§164.310(a)(2)(ii)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-PHY-04",
                "title": "Equipment Security and Maintenance",
                "description": "The organization implements controls to protect equipment from theft, loss, and unauthorized access. Equipment is maintained according to manufacturer specifications and service schedules. Off-site equipment is subject to the same security requirements as on-site assets.",
                "objective": "Ensure organizational equipment remains secure and operational.",
                "control_type": "Physical",
                "frequency": "Continuous; scheduled maintenance per equipment type",
                "mappings": {
                    "soc2": ["CC6.4", "CC6.5"],
                    "iso27001": ["A.7.8", "A.7.9", "A.7.10", "A.7.13"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["MA-2", "MA-3", "MA-4", "PE-16"],
                    "pci_dss": ["9.4.3", "9.4.4"],
                    "hipaa": ["§164.310(c)", "§164.310(d)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: OPS - Operations Security
    # =========================================================================
    {
        "id": "OPS",
        "name": "Operations Security",
        "description": "Controls ensuring secure and reliable day-to-day operation of information processing systems.",
        "controls": [
            {
                "id": "CCF-OPS-01",
                "title": "System Hardening",
                "description": "The organization establishes and maintains system hardening standards (benchmarks) for all operating systems, databases, containers, and network devices. Systems are hardened prior to production deployment and configuration compliance is continuously monitored against approved baselines (e.g., CIS Benchmarks).",
                "objective": "Reduce the attack surface by removing unnecessary services, features, and default configurations.",
                "control_type": "Technical",
                "frequency": "At provisioning; continuous drift detection; quarterly benchmark review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.8", "CC7.1"],
                    "iso27001": ["A.8.9"],
                    "iso27017": ["12.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["CM-6", "CM-7", "SC-2"],
                    "pci_dss": ["2.2", "2.2.1", "2.2.4", "2.2.5"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-OPS-02",
                "title": "Vulnerability Management",
                "description": "The organization maintains a vulnerability management program that includes regular vulnerability scanning (infrastructure, application, container), assessment, prioritization, and remediation. Critical and high vulnerabilities in production are remediated within defined SLAs. Vulnerability assessment results are tracked to closure.",
                "objective": "Identify and remediate security vulnerabilities before they can be exploited.",
                "control_type": "Operational",
                "frequency": "Continuous scanning; remediation per SLA (e.g., Critical: 7 days, High: 30 days)",
                "mappings": {
                    "soc2": ["CC7.1", "CC3.2"],
                    "iso27001": ["A.8.8"],
                    "iso27017": ["12.6.1"],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-01", "PR.IR-01"],
                    "nist_800_53": ["RA-5", "SI-2"],
                    "pci_dss": ["6.3.1", "11.3.1", "11.3.2"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-OPS-03",
                "title": "Patch Management",
                "description": "The organization implements a patch management process that ensures timely application of security patches across operating systems, applications, firmware, and third-party components. Patches are tested before deployment to production and deployed within defined SLAs based on severity.",
                "objective": "Remediate known vulnerabilities through timely patching of systems and software.",
                "control_type": "Operational",
                "frequency": "Continuous; patching per SLA; monthly patching cycles for routine updates",
                "mappings": {
                    "soc2": ["CC7.1"],
                    "iso27001": ["A.8.8", "A.8.19"],
                    "iso27017": ["12.6.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SI-2"],
                    "pci_dss": ["6.3.3"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-OPS-04",
                "title": "Malware Protection",
                "description": "The organization deploys endpoint protection (EPP/EDR) solutions across all endpoints and servers. Anti-malware definitions are updated automatically. Endpoint protection alerts are monitored, triaged, and investigated. Users are prevented from disabling endpoint security controls.",
                "objective": "Detect and prevent malware infections across organizational systems.",
                "control_type": "Technical",
                "frequency": "Continuous; daily signature updates; real-time behavioral analysis",
                "mappings": {
                    "soc2": ["CC6.8", "CC7.1"],
                    "iso27001": ["A.8.7"],
                    "iso27017": ["12.2.1"],
                    "iso27018": [],
                    "nist_csf": ["DE.CM-01"],
                    "nist_800_53": ["SI-3"],
                    "pci_dss": ["5.2", "5.3", "5.3.1", "5.3.2"],
                    "hipaa": ["§164.308(a)(5)(ii)(B)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-OPS-05",
                "title": "Backup Management",
                "description": "The organization performs regular backups of critical data and system configurations. Backups are encrypted, tested for recoverability on a defined schedule, and stored in geographically separated locations. Backup retention periods align with business requirements and regulatory obligations.",
                "objective": "Ensure data and system recoverability in the event of data loss, corruption, or disaster.",
                "control_type": "Operational",
                "frequency": "Daily backups (or per RPO); quarterly restore testing",
                "mappings": {
                    "soc2": ["A1.2", "CC7.5"],
                    "iso27001": ["A.8.13"],
                    "iso27017": ["12.3.1"],
                    "iso27018": ["A.9.4.2"],
                    "nist_csf": ["PR.DS-04"],
                    "nist_800_53": ["CP-9", "CP-10"],
                    "pci_dss": ["9.4.1.1"],
                    "hipaa": ["§164.308(a)(7)(ii)(A)", "§164.310(d)(2)(iv)"],
                    "gdpr": ["Art. 32(1)(c)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-OPS-06",
                "title": "Capacity and Performance Management",
                "description": "The organization monitors system capacity and performance to ensure adequate resources are available to meet operational demands. Capacity thresholds are defined, monitored, and trigger automated scaling or alerting. Capacity planning is performed periodically to anticipate future needs.",
                "objective": "Ensure system availability and performance by proactively managing resource capacity.",
                "control_type": "Operational",
                "frequency": "Continuous monitoring; quarterly capacity planning",
                "mappings": {
                    "soc2": ["A1.1", "A1.2"],
                    "iso27001": ["A.8.6"],
                    "iso27017": ["12.1.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-04"],
                    "nist_800_53": ["CP-2", "SC-5"],
                    "pci_dss": [],
                    "hipaa": ["§164.308(a)(7)(ii)(B)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-OPS-07",
                "title": "Clock Synchronization",
                "description": "The organization synchronizes system clocks across all infrastructure to a consistent, authoritative time source (e.g., NTP, GPS). Accurate time synchronization is essential for log correlation, forensic investigation, and compliance evidence.",
                "objective": "Ensure accurate and consistent timestamps across all systems for auditability.",
                "control_type": "Technical",
                "frequency": "Continuous synchronization; quarterly verification",
                "mappings": {
                    "soc2": ["CC7.2"],
                    "iso27001": ["A.8.17"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["DE.AE-05"],
                    "nist_800_53": ["AU-8"],
                    "pci_dss": ["10.6", "10.6.1", "10.6.2", "10.6.3"],
                    "hipaa": ["§164.312(b)"],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: NET - Network Security
    # =========================================================================
    {
        "id": "NET",
        "name": "Network Security",
        "description": "Controls protecting organizational networks from unauthorized access, threats, and data exfiltration.",
        "controls": [
            {
                "id": "CCF-NET-01",
                "title": "Network Architecture and Segmentation",
                "description": "The organization designs and maintains a network architecture that segments systems based on trust levels, data sensitivity, and functional requirements. Production, staging, development, and corporate environments are logically or physically segmented. Network segmentation is enforced through firewalls, VPCs, security groups, or equivalent controls.",
                "objective": "Limit the blast radius of security incidents and enforce data isolation.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual architecture review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.22"],
                    "iso27017": ["13.1.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SC-7", "AC-4"],
                    "pci_dss": ["1.2.1", "1.3.1", "1.3.2", "1.4.1"],
                    "hipaa": ["§164.312(e)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-NET-02",
                "title": "Firewall and Security Group Management",
                "description": "The organization implements and maintains firewalls, security groups, and network ACLs to control traffic flow between network segments and to/from the internet. Firewall rules follow deny-by-default principles, are documented with business justification, and are reviewed at least semi-annually.",
                "objective": "Control network traffic flow and enforce authorized communication paths.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; semi-annual rule review",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.20", "A.8.21"],
                    "iso27017": ["13.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SC-7(5)"],
                    "pci_dss": ["1.2.1", "1.2.5", "1.2.6", "1.2.7"],
                    "hipaa": ["§164.312(e)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-NET-03",
                "title": "Intrusion Detection and Prevention",
                "description": "The organization deploys network intrusion detection and prevention systems (IDS/IPS) at critical network boundaries and internal segments. Detection signatures and behavioral rules are updated regularly. Alerts are monitored, triaged, and investigated.",
                "objective": "Detect and block malicious network activity.",
                "control_type": "Technical",
                "frequency": "Continuous monitoring; daily signature updates",
                "mappings": {
                    "soc2": ["CC7.2", "CC7.3"],
                    "iso27001": ["A.8.16"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["DE.CM-01"],
                    "nist_800_53": ["SI-4"],
                    "pci_dss": ["11.5", "11.5.1"],
                    "hipaa": ["§164.312(b)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-NET-04",
                "title": "Web Application Firewall",
                "description": "The organization deploys a web application firewall (WAF) in front of all public-facing web applications. The WAF is configured to detect and block common web attacks (OWASP Top 10) and is tuned to minimize false positives while maintaining effective protection.",
                "objective": "Protect public-facing web applications from common attack vectors.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; quarterly rule review",
                "mappings": {
                    "soc2": ["CC6.6"],
                    "iso27001": ["A.8.20"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01", "DE.CM-06"],
                    "nist_800_53": ["SC-7", "SI-4"],
                    "pci_dss": ["6.4.1", "6.4.2"],
                    "hipaa": [],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-NET-05",
                "title": "DDoS Protection",
                "description": "The organization implements distributed denial-of-service (DDoS) protection for public-facing services and infrastructure. Protection includes volumetric, protocol, and application-layer DDoS mitigation. Response procedures and escalation paths are documented and tested.",
                "objective": "Maintain service availability against denial-of-service attacks.",
                "control_type": "Technical",
                "frequency": "Continuous; annual DDoS simulation/tabletop",
                "mappings": {
                    "soc2": ["A1.2", "CC6.6"],
                    "iso27001": ["A.8.20"],
                    "iso27017": ["13.1.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-04"],
                    "nist_800_53": ["SC-5"],
                    "pci_dss": ["11.5"],
                    "hipaa": ["§164.308(a)(7)(i)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-NET-06",
                "title": "DNS Security",
                "description": "The organization implements DNS security controls including DNSSEC where applicable, DNS filtering, and monitoring for DNS-based attacks (e.g., tunneling, cache poisoning). Internal DNS is separated from external DNS resolution.",
                "objective": "Protect DNS infrastructure from manipulation and abuse.",
                "control_type": "Technical",
                "frequency": "Continuous; annual configuration review",
                "mappings": {
                    "soc2": ["CC6.6", "CC7.1"],
                    "iso27001": ["A.8.20"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SC-20", "SC-21", "SC-22"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: SDL - Secure Development Lifecycle
    # =========================================================================
    {
        "id": "SDL",
        "name": "Secure Development Lifecycle",
        "description": "Controls ensuring security is integrated throughout the software development lifecycle from design through deployment.",
        "controls": [
            {
                "id": "CCF-SDL-01",
                "title": "Secure Development Policy",
                "description": "The organization establishes a secure development policy that mandates security activities throughout the software development lifecycle (SDLC). The policy covers secure coding standards, security testing requirements, code review expectations, and security approval gates.",
                "objective": "Ensure security is a first-class requirement throughout the development process.",
                "control_type": "Administrative",
                "frequency": "Annual review; update for new technology stacks",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.25", "A.8.26"],
                    "iso27017": ["14.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SA-3", "SA-15"],
                    "pci_dss": ["6.2", "6.2.1"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 25"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-SDL-02",
                "title": "Security Requirements in Design",
                "description": "The organization incorporates security and privacy requirements into the design phase of application and system development. Threat modeling or security design reviews are conducted for new features, significant changes, and new integrations.",
                "objective": "Identify and address security risks early in the design phase.",
                "control_type": "Operational",
                "frequency": "Per feature/project; at design phase",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.25"],
                    "iso27017": ["14.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SA-8", "SA-11"],
                    "pci_dss": ["6.2.1"],
                    "hipaa": [],
                    "gdpr": ["Art. 25(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-SDL-03",
                "title": "Code Review",
                "description": "The organization requires peer code review for all changes to production code prior to merge and deployment. Code reviews evaluate functional correctness, security implications, coding standards compliance, and identify potential vulnerabilities or logic flaws.",
                "objective": "Catch defects and security issues before code reaches production.",
                "control_type": "Operational",
                "frequency": "Per code change (every pull request/merge request)",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.25"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["SA-11"],
                    "pci_dss": ["6.2.3.1"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-SDL-04",
                "title": "Static and Dynamic Application Security Testing",
                "description": "The organization integrates static application security testing (SAST) and dynamic application security testing (DAST) into the CI/CD pipeline. SAST scans are performed on every build. DAST scans are performed against staging/pre-production environments on a regular cadence. Findings are triaged, prioritized, and remediated per defined SLAs.",
                "objective": "Identify application-level vulnerabilities through automated testing.",
                "control_type": "Technical",
                "frequency": "SAST: every build; DAST: per release or at minimum monthly",
                "mappings": {
                    "soc2": ["CC7.1", "CC8.1"],
                    "iso27001": ["A.8.25", "A.8.29"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01", "DE.CM-06"],
                    "nist_800_53": ["SA-11"],
                    "pci_dss": ["6.2.4", "11.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-SDL-05",
                "title": "Penetration Testing",
                "description": "The organization conducts penetration testing of production applications and infrastructure at least annually and upon significant changes. Testing includes both external and internal perspectives, is performed by qualified testers (internal or third-party), and findings are remediated within defined SLAs.",
                "objective": "Validate security controls through adversarial testing of production systems.",
                "control_type": "Operational",
                "frequency": "Annual (minimum); upon major release; continuous for bug bounty programs",
                "mappings": {
                    "soc2": ["CC4.1", "CC7.1"],
                    "iso27001": ["A.8.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-01"],
                    "nist_800_53": ["CA-8"],
                    "pci_dss": ["11.4", "11.4.1"],
                    "hipaa": ["§164.308(a)(8)"],
                    "gdpr": ["Art. 32(1)(d)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-SDL-06",
                "title": "Software Dependency and Supply Chain Security",
                "description": "The organization maintains controls over third-party software dependencies including software composition analysis (SCA), vulnerability scanning of open-source libraries, license compliance checking, and software bill of materials (SBOM) generation. Vulnerable dependencies are remediated per defined SLAs.",
                "objective": "Manage security risks from third-party and open-source software components.",
                "control_type": "Technical",
                "frequency": "Continuous (integrated into CI/CD); quarterly dependency review",
                "mappings": {
                    "soc2": ["CC7.1", "CC9.2"],
                    "iso27001": ["A.8.28"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-01"],
                    "nist_800_53": ["SA-12", "SR-3", "SR-4"],
                    "pci_dss": ["6.3.2"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-SDL-07",
                "title": "Environment Separation",
                "description": "The organization maintains separate environments for development, testing/staging, and production. Production data is not used in non-production environments without anonymization/masking. Access to production is restricted to authorized personnel and deployments follow the approved change management process.",
                "objective": "Prevent unauthorized changes and data exposure through environment isolation.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual environment architecture review",
                "mappings": {
                    "soc2": ["CC6.1", "CC8.1"],
                    "iso27001": ["A.8.25", "A.8.31"],
                    "iso27017": ["12.1.4"],
                    "iso27018": ["A.11.6"],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["CM-4", "SA-11"],
                    "pci_dss": ["6.5.1", "6.5.2", "6.5.3", "6.5.4"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: CHM - Change Management
    # =========================================================================
    {
        "id": "CHM",
        "name": "Change Management",
        "description": "Controls governing the management of changes to information systems, infrastructure, and applications throughout their lifecycle.",
        "controls": [
            {
                "id": "CCF-CHM-01",
                "title": "Change Management Policy and Process",
                "description": "The organization establishes a change management policy that defines the process for requesting, evaluating, approving, implementing, and reviewing changes to information systems. The process covers standard, normal, and emergency change types with appropriate governance for each.",
                "objective": "Ensure changes are controlled, authorized, and traceable.",
                "control_type": "Administrative",
                "frequency": "Annual policy review; per-change execution",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.32"],
                    "iso27017": ["12.1.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.IP-03"],
                    "nist_800_53": ["CM-1", "CM-3"],
                    "pci_dss": ["6.5.1"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CHM-02",
                "title": "Change Authorization and Approval",
                "description": "All changes to production systems require documented approval prior to deployment. Approval authority is commensurate with the risk and scope of the change. The developer/requester cannot self-approve changes to production (segregation of duties).",
                "objective": "Ensure no unauthorized changes are deployed to production.",
                "control_type": "Operational",
                "frequency": "Per change",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.32"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IP-03"],
                    "nist_800_53": ["CM-3(1)"],
                    "pci_dss": ["6.5.1", "6.5.2"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CHM-03",
                "title": "Change Testing and Validation",
                "description": "Changes are tested in a non-production environment prior to production deployment. Testing includes functional validation, regression testing, and security impact assessment as appropriate. Automated testing is integrated into the CI/CD pipeline.",
                "objective": "Prevent defects and security issues from being introduced through changes.",
                "control_type": "Operational",
                "frequency": "Per change",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.29", "A.8.32"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IP-03"],
                    "nist_800_53": ["CM-4", "SA-11"],
                    "pci_dss": ["6.2.3", "6.5.3"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CHM-04",
                "title": "Emergency Change Process",
                "description": "The organization maintains an emergency change process for urgent production fixes that cannot follow the standard change process. Emergency changes require post-implementation review, retroactive approval, and documentation within a defined timeframe.",
                "objective": "Enable rapid response to production issues while maintaining accountability.",
                "control_type": "Operational",
                "frequency": "Per occurrence; retroactive review within 48 hours",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.32"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IP-03"],
                    "nist_800_53": ["CM-3(1)"],
                    "pci_dss": ["6.5.1"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CHM-05",
                "title": "Configuration Management",
                "description": "The organization maintains and enforces approved configuration baselines for systems, applications, and infrastructure. Configuration is managed as code (IaC) where possible, version controlled, and deviations from approved baselines are detected and remediated.",
                "objective": "Maintain known-good system configurations and detect unauthorized deviations.",
                "control_type": "Technical",
                "frequency": "Continuous (IaC/drift detection); quarterly baseline review",
                "mappings": {
                    "soc2": ["CC7.1", "CC8.1"],
                    "iso27001": ["A.8.9"],
                    "iso27017": ["12.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IP-01"],
                    "nist_800_53": ["CM-2", "CM-3", "CM-6"],
                    "pci_dss": ["2.2"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CHM-06",
                "title": "Release Management",
                "description": "The organization implements a release management process that governs the packaging, scheduling, and deployment of software releases to production. Release procedures include rollback plans, deployment verification, and post-deployment monitoring.",
                "objective": "Ensure reliable and controlled deployment of software to production.",
                "control_type": "Operational",
                "frequency": "Per release",
                "mappings": {
                    "soc2": ["CC8.1"],
                    "iso27001": ["A.8.32"],
                    "iso27017": ["14.2.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.IP-03"],
                    "nist_800_53": ["CM-3", "SA-10"],
                    "pci_dss": ["6.5.1", "6.5.4"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: LOG - Logging and Monitoring
    # =========================================================================
    {
        "id": "LOG",
        "name": "Logging and Monitoring",
        "description": "Controls ensuring comprehensive logging, centralized monitoring, and detection of security-relevant events across organizational systems.",
        "controls": [
            {
                "id": "CCF-LOG-01",
                "title": "Audit Logging Standards",
                "description": "The organization defines and enforces audit logging standards specifying what events must be logged, the minimum data fields per log entry (who, what, when, where, outcome), and which systems are in scope. Logging is enabled for authentication events, access decisions, administrative actions, data access, and configuration changes.",
                "objective": "Ensure security-relevant events are captured consistently across all systems.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual logging coverage review",
                "mappings": {
                    "soc2": ["CC7.2"],
                    "iso27001": ["A.8.15"],
                    "iso27017": ["12.4.1"],
                    "iso27018": ["A.12.4.1"],
                    "nist_csf": ["DE.AE-03"],
                    "nist_800_53": ["AU-2", "AU-3"],
                    "pci_dss": ["10.2", "10.2.1", "10.2.2"],
                    "hipaa": ["§164.312(b)"],
                    "gdpr": ["Art. 30"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-LOG-02",
                "title": "Centralized Log Collection and Aggregation",
                "description": "The organization collects and aggregates logs from all in-scope systems into a centralized SIEM or log management platform. Log collection covers cloud infrastructure, applications, databases, identity systems, network devices, and security tools.",
                "objective": "Enable correlated analysis and investigation by centralizing log data.",
                "control_type": "Technical",
                "frequency": "Continuous; monthly coverage review",
                "mappings": {
                    "soc2": ["CC7.2", "CC7.3"],
                    "iso27001": ["A.8.15"],
                    "iso27017": ["12.4.1"],
                    "iso27018": [],
                    "nist_csf": ["DE.AE-03"],
                    "nist_800_53": ["AU-6", "SI-4"],
                    "pci_dss": ["10.3", "10.3.3"],
                    "hipaa": ["§164.312(b)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-LOG-03",
                "title": "Log Retention",
                "description": "The organization retains audit logs for a minimum period defined by regulatory and business requirements. Log retention periods meet or exceed requirements of applicable frameworks (typically 1 year minimum, with 90 days online). Logs are protected from unauthorized modification or deletion.",
                "objective": "Ensure log data is available for investigation, audit, and compliance purposes.",
                "control_type": "Technical",
                "frequency": "Continuous; annual retention policy review",
                "mappings": {
                    "soc2": ["CC7.2"],
                    "iso27001": ["A.8.15"],
                    "iso27017": ["12.4.1"],
                    "iso27018": ["A.12.4.1"],
                    "nist_csf": ["DE.AE-03"],
                    "nist_800_53": ["AU-11"],
                    "pci_dss": ["10.5.1"],
                    "hipaa": ["§164.312(b)"],
                    "gdpr": ["Art. 5(1)(e)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-LOG-04",
                "title": "Security Monitoring and Alerting",
                "description": "The organization implements security monitoring with defined detection rules, alerting thresholds, and escalation procedures. Monitoring covers indicators of compromise (IoCs), anomalous behavior, policy violations, and high-risk events. Alerts are triaged and investigated within defined SLAs.",
                "objective": "Detect security incidents and threats in a timely manner through active monitoring.",
                "control_type": "Technical",
                "frequency": "Continuous (24/7 where applicable); monthly detection rule review",
                "mappings": {
                    "soc2": ["CC7.2", "CC7.3"],
                    "iso27001": ["A.8.16"],
                    "iso27017": ["12.4.1"],
                    "iso27018": [],
                    "nist_csf": ["DE.CM-01", "DE.CM-06", "DE.AE-02"],
                    "nist_800_53": ["SI-4", "IR-4"],
                    "pci_dss": ["10.4.1", "10.7"],
                    "hipaa": ["§164.308(a)(1)(ii)(D)", "§164.312(b)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-LOG-05",
                "title": "Log Integrity Protection",
                "description": "The organization protects log data from unauthorized modification, deletion, and tampering. Controls include write-once storage, separate log storage accounts, access restrictions to log management systems, and integrity verification mechanisms.",
                "objective": "Ensure log data remains trustworthy for investigation and compliance purposes.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual integrity review",
                "mappings": {
                    "soc2": ["CC7.2"],
                    "iso27001": ["A.8.15"],
                    "iso27017": ["12.4.2"],
                    "iso27018": [],
                    "nist_csf": ["DE.AE-03"],
                    "nist_800_53": ["AU-9", "AU-10"],
                    "pci_dss": ["10.3.2"],
                    "hipaa": ["§164.312(b)", "§164.312(c)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: INC - Incident Management
    # =========================================================================
    {
        "id": "INC",
        "name": "Incident Management",
        "description": "Controls governing the detection, response, management, and resolution of security incidents.",
        "controls": [
            {
                "id": "CCF-INC-01",
                "title": "Incident Response Plan",
                "description": "The organization maintains a documented incident response plan that defines incident classification, roles and responsibilities, communication procedures, escalation paths, containment strategies, and post-incident review processes. The plan is tested at least annually through tabletop exercises or simulations.",
                "objective": "Ensure the organization can respond to security incidents in a structured and effective manner.",
                "control_type": "Administrative",
                "frequency": "Annual review and testing; update after significant incidents",
                "mappings": {
                    "soc2": ["CC7.3", "CC7.4", "CC7.5"],
                    "iso27001": ["A.5.24", "A.5.25", "A.5.26"],
                    "iso27017": ["16.1.1"],
                    "iso27018": ["A.16.1.1"],
                    "nist_csf": ["RS.MA-01", "RS.MA-02"],
                    "nist_800_53": ["IR-1", "IR-8"],
                    "pci_dss": ["12.10.1", "12.10.2"],
                    "hipaa": ["§164.308(a)(6)(i)", "§164.308(a)(6)(ii)"],
                    "gdpr": ["Art. 33", "Art. 34"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-INC-02",
                "title": "Incident Detection and Reporting",
                "description": "The organization implements mechanisms for detecting and reporting security incidents including automated detection through monitoring systems, employee reporting channels, and external reporting mechanisms (e.g., responsible disclosure program). All personnel are trained to recognize and report potential security incidents.",
                "objective": "Enable timely identification and reporting of security incidents from all sources.",
                "control_type": "Operational",
                "frequency": "Continuous; training at onboarding and annually",
                "mappings": {
                    "soc2": ["CC7.2", "CC7.3"],
                    "iso27001": ["A.6.8", "A.8.16"],
                    "iso27017": ["16.1.2"],
                    "iso27018": [],
                    "nist_csf": ["DE.AE-02", "DE.AE-06"],
                    "nist_800_53": ["IR-4", "IR-6"],
                    "pci_dss": ["12.10.5"],
                    "hipaa": ["§164.308(a)(6)(ii)"],
                    "gdpr": ["Art. 33(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-INC-03",
                "title": "Incident Containment, Eradication, and Recovery",
                "description": "The organization implements procedures for containing active security incidents, eradicating the root cause, and recovering affected systems. Containment strategies are predefined for common incident types. Recovery procedures include system restoration, data integrity verification, and return-to-normal-operations criteria.",
                "objective": "Minimize the impact of security incidents and restore normal operations.",
                "control_type": "Operational",
                "frequency": "Per incident",
                "mappings": {
                    "soc2": ["CC7.4", "CC7.5"],
                    "iso27001": ["A.5.26"],
                    "iso27017": ["16.1.5"],
                    "iso27018": [],
                    "nist_csf": ["RS.MI-01", "RS.MI-02", "RC.RP-01"],
                    "nist_800_53": ["IR-4", "IR-5"],
                    "pci_dss": ["12.10.1"],
                    "hipaa": ["§164.308(a)(7)(i)"],
                    "gdpr": ["Art. 33"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-INC-04",
                "title": "Incident Communication and Notification",
                "description": "The organization maintains communication procedures for security incidents including internal escalation to leadership, notification to affected customers, and reporting to regulatory authorities as required. Communication templates and notification criteria are predefined. Breach notification complies with applicable legal timeframes (e.g., GDPR 72 hours).",
                "objective": "Ensure timely and appropriate communication during security incidents.",
                "control_type": "Administrative",
                "frequency": "Per incident; annual template review",
                "mappings": {
                    "soc2": ["CC2.3", "CC7.3", "CC7.4"],
                    "iso27001": ["A.5.24", "A.5.25"],
                    "iso27017": ["16.1.2"],
                    "iso27018": ["A.9.1"],
                    "nist_csf": ["RS.CO-02", "RS.CO-03"],
                    "nist_800_53": ["IR-6", "IR-7"],
                    "pci_dss": ["12.10.1"],
                    "hipaa": ["§164.308(a)(6)(ii)", "§164.404", "§164.408"],
                    "gdpr": ["Art. 33", "Art. 34"],
                    "ccpa": ["§1798.150(a)"]
                }
            },
            {
                "id": "CCF-INC-05",
                "title": "Post-Incident Review and Lessons Learned",
                "description": "The organization conducts post-incident reviews (blameless postmortems) for all significant security incidents. Reviews identify root causes, evaluate response effectiveness, document lessons learned, and generate action items for improvement. Findings are incorporated into the security program.",
                "objective": "Continuously improve incident response capabilities and prevent recurrence.",
                "control_type": "Operational",
                "frequency": "After each significant incident; within 5 business days of resolution",
                "mappings": {
                    "soc2": ["CC4.2", "CC7.5"],
                    "iso27001": ["A.5.27"],
                    "iso27017": ["16.1.6"],
                    "iso27018": [],
                    "nist_csf": ["RS.IM-01", "RS.IM-02"],
                    "nist_800_53": ["IR-4(4)"],
                    "pci_dss": ["12.10.2"],
                    "hipaa": ["§164.308(a)(6)(ii)"],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: BCP - Business Continuity and Disaster Recovery
    # =========================================================================
    {
        "id": "BCP",
        "name": "Business Continuity and Disaster Recovery",
        "description": "Controls ensuring the organization can maintain critical operations and recover from disruptive events.",
        "controls": [
            {
                "id": "CCF-BCP-01",
                "title": "Business Continuity Plan",
                "description": "The organization maintains a business continuity plan (BCP) that identifies critical business functions, dependencies, and recovery priorities. The plan defines procedures for maintaining operations during disruptive events and is tested at least annually.",
                "objective": "Ensure the organization can continue essential operations during disruptions.",
                "control_type": "Administrative",
                "frequency": "Annual review and testing; update upon significant change",
                "mappings": {
                    "soc2": ["A1.2", "A1.3"],
                    "iso27001": ["A.5.29", "A.5.30"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["RC.RP-01", "RC.RP-02"],
                    "nist_800_53": ["CP-1", "CP-2"],
                    "pci_dss": [],
                    "hipaa": ["§164.308(a)(7)(i)", "§164.308(a)(7)(ii)(B)"],
                    "gdpr": ["Art. 32(1)(c)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-BCP-02",
                "title": "Disaster Recovery Plan",
                "description": "The organization maintains a disaster recovery plan (DRP) that defines procedures for restoring IT systems, applications, and data following a disaster or major disruption. The plan specifies recovery time objectives (RTO) and recovery point objectives (RPO) for critical systems.",
                "objective": "Enable timely recovery of technology systems and data after a disruptive event.",
                "control_type": "Administrative",
                "frequency": "Annual review; testing per CCF-BCP-03",
                "mappings": {
                    "soc2": ["A1.2", "CC7.5"],
                    "iso27001": ["A.5.30", "A.8.14"],
                    "iso27017": ["17.1.1"],
                    "iso27018": [],
                    "nist_csf": ["RC.RP-01"],
                    "nist_800_53": ["CP-2", "CP-10"],
                    "pci_dss": [],
                    "hipaa": ["§164.308(a)(7)(ii)(B)", "§164.310(a)(2)(i)"],
                    "gdpr": ["Art. 32(1)(c)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-BCP-03",
                "title": "BCP/DR Testing and Exercising",
                "description": "The organization tests business continuity and disaster recovery plans at least annually through tabletop exercises, functional tests, or full-scale simulations. Tests validate recovery procedures, RTO/RPO achievement, communication protocols, and personnel preparedness. Test results are documented and findings drive plan improvements.",
                "objective": "Validate that BCP/DR plans are effective and personnel are prepared to execute them.",
                "control_type": "Operational",
                "frequency": "Annual (minimum); semi-annual for critical systems",
                "mappings": {
                    "soc2": ["A1.3"],
                    "iso27001": ["A.5.30"],
                    "iso27017": ["17.1.2"],
                    "iso27018": [],
                    "nist_csf": ["RC.RP-03"],
                    "nist_800_53": ["CP-4"],
                    "pci_dss": [],
                    "hipaa": ["§164.308(a)(7)(ii)(D)"],
                    "gdpr": ["Art. 32(1)(d)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-BCP-04",
                "title": "High Availability and Redundancy",
                "description": "The organization designs critical systems with redundancy and high availability capabilities including multi-region/multi-AZ deployment, load balancing, automatic failover, and elimination of single points of failure. Availability architecture is documented and validated through testing.",
                "objective": "Minimize service disruptions through resilient system architecture.",
                "control_type": "Technical",
                "frequency": "Continuous; annual architecture review; semi-annual failover testing",
                "mappings": {
                    "soc2": ["A1.1", "A1.2"],
                    "iso27001": ["A.8.14"],
                    "iso27017": ["17.2.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-04", "RC.RP-01"],
                    "nist_800_53": ["CP-7", "CP-8", "SC-36"],
                    "pci_dss": [],
                    "hipaa": ["§164.308(a)(7)(ii)(C)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: VND - Vendor and Third-Party Management
    # =========================================================================
    {
        "id": "VND",
        "name": "Vendor and Third-Party Management",
        "description": "Controls governing the assessment, selection, monitoring, and management of third-party service providers and vendors.",
        "controls": [
            {
                "id": "CCF-VND-01",
                "title": "Vendor Risk Assessment",
                "description": "The organization conducts risk assessments of third-party vendors prior to engagement and periodically thereafter. Assessments evaluate the vendor's security posture, certifications, data handling practices, and business continuity capabilities. Assessment rigor is proportionate to the criticality and data access of the vendor relationship.",
                "objective": "Evaluate and manage security risks introduced through third-party relationships.",
                "control_type": "Administrative",
                "frequency": "Pre-engagement; annual reassessment for critical vendors",
                "mappings": {
                    "soc2": ["CC9.2"],
                    "iso27001": ["A.5.19", "A.5.20", "A.5.21"],
                    "iso27017": ["CLD.6.3"],
                    "iso27018": ["A.15.1.1"],
                    "nist_csf": ["GV.SC-03", "GV.SC-06"],
                    "nist_800_53": ["SA-9", "SR-2", "SR-5", "SR-6"],
                    "pci_dss": ["12.8", "12.8.1", "12.8.2"],
                    "hipaa": ["§164.308(b)(1)", "§164.314(a)(1)"],
                    "gdpr": ["Art. 28(1)", "Art. 28(2)"],
                    "ccpa": ["§1798.140(w)"]
                }
            },
            {
                "id": "CCF-VND-02",
                "title": "Vendor Security Requirements and Contracts",
                "description": "The organization includes security and privacy requirements in vendor contracts including data protection obligations, incident notification requirements, audit rights, data return/destruction provisions, and compliance with applicable regulations. Contracts are reviewed by legal and security prior to execution.",
                "objective": "Establish binding security obligations for vendors handling organizational data.",
                "control_type": "Administrative",
                "frequency": "At contract execution; renewal; upon material scope change",
                "mappings": {
                    "soc2": ["CC9.2"],
                    "iso27001": ["A.5.19", "A.5.20"],
                    "iso27017": ["CLD.6.3"],
                    "iso27018": ["A.15.1.2"],
                    "nist_csf": ["GV.SC-05"],
                    "nist_800_53": ["SA-4", "SA-9"],
                    "pci_dss": ["12.8.2", "12.8.5"],
                    "hipaa": ["§164.308(b)(1)", "§164.314(a)(2)"],
                    "gdpr": ["Art. 28(3)", "Art. 28(9)"],
                    "ccpa": ["§1798.140(w)"]
                }
            },
            {
                "id": "CCF-VND-03",
                "title": "Vendor Monitoring and Oversight",
                "description": "The organization monitors vendor compliance with security requirements on an ongoing basis. Monitoring includes review of vendor certifications and audit reports (e.g., SOC 2), tracking of vendor security incidents, and periodic reassessment of vendor risk ratings.",
                "objective": "Ensure vendors maintain required security standards throughout the relationship.",
                "control_type": "Operational",
                "frequency": "Annual vendor review; continuous for critical incidents; quarterly for tier-1 vendors",
                "mappings": {
                    "soc2": ["CC9.2", "CC4.1"],
                    "iso27001": ["A.5.22"],
                    "iso27017": ["15.2.1"],
                    "iso27018": [],
                    "nist_csf": ["GV.SC-09", "GV.SC-10"],
                    "nist_800_53": ["SA-9(2)", "CA-7"],
                    "pci_dss": ["12.8.4"],
                    "hipaa": ["§164.308(b)(1)"],
                    "gdpr": ["Art. 28(3)(h)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-VND-04",
                "title": "Subprocessor Management",
                "description": "The organization maintains visibility into and control over vendor subprocessors (fourth parties) that may access organizational data. Vendors are required to notify the organization of new subprocessors and ensure subprocessors meet equivalent security standards. A current subprocessor list is maintained and accessible to customers.",
                "objective": "Extend security and privacy oversight to downstream service providers.",
                "control_type": "Administrative",
                "frequency": "Continuous notification; annual subprocessor review",
                "mappings": {
                    "soc2": ["CC9.2"],
                    "iso27001": ["A.5.19", "A.5.21"],
                    "iso27017": ["CLD.6.3"],
                    "iso27018": ["A.15.1.3"],
                    "nist_csf": ["GV.SC-07"],
                    "nist_800_53": ["SA-9", "SR-6"],
                    "pci_dss": ["12.8.5"],
                    "hipaa": ["§164.314(a)(2)(i)"],
                    "gdpr": ["Art. 28(2)", "Art. 28(4)"],
                    "ccpa": ["§1798.140(w)"]
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: PRI - Privacy
    # =========================================================================
    {
        "id": "PRI",
        "name": "Privacy",
        "description": "Controls governing the collection, processing, storage, and protection of personal data in compliance with privacy regulations and organizational commitments.",
        "controls": [
            {
                "id": "CCF-PRI-01",
                "title": "Privacy Policy and Notice",
                "description": "The organization maintains a public-facing privacy policy/notice that clearly communicates how personal data is collected, used, shared, and retained. The notice covers data categories, purposes of processing, third-party sharing, individual rights, and contact information. The notice is reviewed at least annually and updated to reflect changes in practices.",
                "objective": "Provide transparent disclosure of personal data practices to data subjects.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon material practice change",
                "mappings": {
                    "soc2": ["P1.1", "P1.2"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.2.1"],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PT-3", "PT-5"],
                    "pci_dss": [],
                    "hipaa": ["§164.520"],
                    "gdpr": ["Art. 12", "Art. 13", "Art. 14"],
                    "ccpa": ["§1798.100(a)", "§1798.110(a)", "§1798.130"]
                }
            },
            {
                "id": "CCF-PRI-02",
                "title": "Data Processing Inventory (RoPA)",
                "description": "The organization maintains a record of processing activities (RoPA) that documents all personal data processing operations, including data categories, purposes, legal bases, recipients, transfer mechanisms, and retention periods. The inventory is maintained current and available for regulatory review.",
                "objective": "Maintain a comprehensive and current inventory of personal data processing activities.",
                "control_type": "Administrative",
                "frequency": "Continuous maintenance; quarterly review; update upon new processing activities",
                "mappings": {
                    "soc2": ["P1.1"],
                    "iso27001": ["A.5.9"],
                    "iso27017": [],
                    "iso27018": ["A.2.5"],
                    "nist_csf": ["ID.AM-05"],
                    "nist_800_53": ["PT-3", "PM-25"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": ["Art. 30"],
                    "ccpa": ["§1798.100(a)"]
                }
            },
            {
                "id": "CCF-PRI-03",
                "title": "Consent Management",
                "description": "The organization obtains and manages consent for personal data processing where consent is the applicable legal basis. Consent is freely given, specific, informed, and unambiguous. Mechanisms are in place to record consent, honor withdrawal of consent, and adjust processing accordingly.",
                "objective": "Ensure lawful consent-based processing and respect individual consent preferences.",
                "control_type": "Operational",
                "frequency": "Per data collection event; continuous consent record maintenance",
                "mappings": {
                    "soc2": ["P2.1"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.2.1"],
                    "nist_csf": [],
                    "nist_800_53": ["PT-4"],
                    "pci_dss": [],
                    "hipaa": ["§164.508"],
                    "gdpr": ["Art. 6(1)(a)", "Art. 7"],
                    "ccpa": ["§1798.120", "§1798.135"]
                }
            },
            {
                "id": "CCF-PRI-04",
                "title": "Data Subject Rights Management",
                "description": "The organization implements processes and mechanisms to receive, verify, and respond to data subject rights requests including access, rectification, deletion, portability, restriction, and objection. Requests are fulfilled within legally required timeframes.",
                "objective": "Enable individuals to exercise their privacy rights effectively and within legal timeframes.",
                "control_type": "Operational",
                "frequency": "Per request; fulfillment within 30 days (GDPR) or 45 days (CCPA)",
                "mappings": {
                    "soc2": ["P4.1", "P4.2", "P4.3"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.1.1", "A.2.2"],
                    "nist_csf": [],
                    "nist_800_53": ["IP-1", "IP-2", "IP-3", "IP-4"],
                    "pci_dss": [],
                    "hipaa": ["§164.524", "§164.526", "§164.528"],
                    "gdpr": ["Art. 15", "Art. 16", "Art. 17", "Art. 18", "Art. 20", "Art. 21"],
                    "ccpa": ["§1798.100", "§1798.105", "§1798.110", "§1798.115"]
                }
            },
            {
                "id": "CCF-PRI-05",
                "title": "Data Minimization and Purpose Limitation",
                "description": "The organization limits the collection and processing of personal data to what is necessary and proportionate for the specified, legitimate purposes. Data is not repurposed beyond original collection purposes without additional legal basis or consent. Processing activities are regularly reviewed to identify and eliminate unnecessary data collection.",
                "objective": "Reduce privacy risk by limiting data collection and use to what is necessary.",
                "control_type": "Administrative",
                "frequency": "At system design; annual review of data collection practices",
                "mappings": {
                    "soc2": ["P3.1", "P3.2"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.2.1", "A.2.5"],
                    "nist_csf": [],
                    "nist_800_53": ["PT-2", "PT-3"],
                    "pci_dss": ["3.1"],
                    "hipaa": ["§164.502(b)", "§164.514"],
                    "gdpr": ["Art. 5(1)(b)", "Art. 5(1)(c)"],
                    "ccpa": ["§1798.100(c)"]
                }
            },
            {
                "id": "CCF-PRI-06",
                "title": "Data Retention and Disposal",
                "description": "The organization defines and enforces data retention schedules that specify how long personal data and other sensitive data is retained and when it must be securely disposed. Retention periods are based on legal requirements, contractual obligations, and business necessity. Disposal is performed using methods appropriate to the data sensitivity.",
                "objective": "Ensure personal data is not retained beyond its useful or legally required period.",
                "control_type": "Operational",
                "frequency": "Continuous enforcement; annual retention schedule review",
                "mappings": {
                    "soc2": ["P5.1", "P5.2", "C1.2"],
                    "iso27001": ["A.8.10"],
                    "iso27017": [],
                    "iso27018": ["A.9.4.2"],
                    "nist_csf": [],
                    "nist_800_53": ["SI-12", "MP-6"],
                    "pci_dss": ["3.2.1", "9.4.5", "9.4.6"],
                    "hipaa": ["§164.530(j)"],
                    "gdpr": ["Art. 5(1)(e)", "Art. 17"],
                    "ccpa": ["§1798.105"]
                }
            },
            {
                "id": "CCF-PRI-07",
                "title": "Privacy Impact Assessments (DPIA)",
                "description": "The organization conducts data protection impact assessments (DPIAs) or privacy impact assessments (PIAs) for new or significantly changed processing activities that present high risk to individuals. Assessments evaluate necessity, proportionality, risks, and mitigating measures. Results inform processing decisions and are documented.",
                "objective": "Identify and mitigate privacy risks before initiating high-risk data processing.",
                "control_type": "Administrative",
                "frequency": "Prior to new high-risk processing; upon significant change to existing processing",
                "mappings": {
                    "soc2": ["P1.1"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.11.3"],
                    "nist_csf": ["GV.RM-01"],
                    "nist_800_53": ["PT-5", "RA-8"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": ["Art. 35", "Art. 36"],
                    "ccpa": ["§1798.185(a)(15)"]
                }
            },
            {
                "id": "CCF-PRI-08",
                "title": "Cross-Border Data Transfers",
                "description": "The organization implements appropriate safeguards for transfers of personal data to countries or jurisdictions that do not provide an adequate level of data protection. Transfer mechanisms include Standard Contractual Clauses (SCCs), Binding Corporate Rules (BCRs), or other approved mechanisms. Transfer impact assessments are performed as required.",
                "objective": "Ensure lawful and secure transfer of personal data across jurisdictional boundaries.",
                "control_type": "Administrative",
                "frequency": "Per transfer mechanism; annual review of transfer safeguards",
                "mappings": {
                    "soc2": ["P6.1"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.11.1"],
                    "nist_csf": [],
                    "nist_800_53": ["PT-6"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": ["Art. 44", "Art. 45", "Art. 46", "Art. 49"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-PRI-09",
                "title": "Data Protection Officer / Privacy Function",
                "description": "The organization designates a privacy function or Data Protection Officer (DPO) responsible for overseeing privacy compliance, advising on data protection matters, and serving as a point of contact for data subjects and regulatory authorities. The DPO/privacy function has appropriate authority, resources, and independence.",
                "objective": "Ensure dedicated oversight and expertise for privacy compliance.",
                "control_type": "Administrative",
                "frequency": "Continuous; annual assessment of privacy function resources",
                "mappings": {
                    "soc2": ["P1.1"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": ["A.11.4"],
                    "nist_csf": ["GV.RR-01"],
                    "nist_800_53": ["PM-18", "PM-19"],
                    "pci_dss": [],
                    "hipaa": ["§164.530(a)(1)"],
                    "gdpr": ["Art. 37", "Art. 38", "Art. 39"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-PRI-10",
                "title": "Do Not Sell / Share Controls",
                "description": "The organization implements controls to honor 'do not sell or share my personal information' requests as required by applicable privacy regulations. Opt-out mechanisms are prominently displayed and technically enforced across all data processing systems and third-party integrations.",
                "objective": "Ensure compliance with consumer opt-out rights regarding data sale and sharing.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; per opt-out request",
                "mappings": {
                    "soc2": ["P2.1"],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": [],
                    "nist_800_53": ["PT-4"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": ["Art. 21"],
                    "ccpa": ["§1798.120", "§1798.135"]
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: DGV - Data Governance
    # =========================================================================
    {
        "id": "DGV",
        "name": "Data Governance",
        "description": "Controls governing data integrity, quality, and protection throughout the data lifecycle.",
        "controls": [
            {
                "id": "CCF-DGV-01",
                "title": "Data Integrity Controls",
                "description": "The organization implements controls to ensure the accuracy, completeness, and consistency of data during input, processing, and output. Data validation rules, checksums, and reconciliation processes are used to detect and prevent data corruption or unauthorized modification.",
                "objective": "Ensure data remains accurate and unaltered throughout processing.",
                "control_type": "Technical",
                "frequency": "Continuous; per transaction/processing event",
                "mappings": {
                    "soc2": ["PI1.1", "PI1.2", "PI1.3"],
                    "iso27001": ["A.8.11"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-06"],
                    "nist_800_53": ["SI-7", "SI-10"],
                    "pci_dss": [],
                    "hipaa": ["§164.312(c)(1)", "§164.312(c)(2)"],
                    "gdpr": ["Art. 5(1)(d)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-DGV-02",
                "title": "Data Loss Prevention",
                "description": "The organization implements data loss prevention (DLP) controls to detect and prevent unauthorized exfiltration of sensitive data. DLP controls cover email, web uploads, cloud storage, endpoint transfers, and API data flows. DLP policies are aligned with data classification levels.",
                "objective": "Prevent unauthorized disclosure or exfiltration of sensitive data.",
                "control_type": "Technical",
                "frequency": "Continuous monitoring and enforcement",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7", "C1.1"],
                    "iso27001": ["A.8.10", "A.8.11", "A.8.12"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-01", "PR.DS-02"],
                    "nist_800_53": ["SC-7", "SI-4"],
                    "pci_dss": [],
                    "hipaa": ["§164.312(e)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": ["§1798.150(a)"]
                }
            },
            {
                "id": "CCF-DGV-03",
                "title": "Data Masking and Anonymization",
                "description": "The organization implements data masking, anonymization, or pseudonymization techniques for sensitive data used in non-production environments, analytics, testing, and reporting. Techniques are validated to ensure data cannot be re-identified without additional information kept separately.",
                "objective": "Reduce exposure of sensitive data in contexts where full data is not required.",
                "control_type": "Technical",
                "frequency": "Per data provisioning event; annual technique review",
                "mappings": {
                    "soc2": ["C1.1", "CC6.1"],
                    "iso27001": ["A.8.11"],
                    "iso27017": [],
                    "iso27018": ["A.10.1"],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["SI-19"],
                    "pci_dss": ["3.4", "3.4.1"],
                    "hipaa": ["§164.514"],
                    "gdpr": ["Art. 25(1)", "Rec. 26"],
                    "ccpa": ["§1798.145(a)(5)"]
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: CMP - Compliance and Audit
    # =========================================================================
    {
        "id": "CMP",
        "name": "Compliance and Audit",
        "description": "Controls governing internal and external compliance monitoring, audit activities, and continuous improvement of the security program.",
        "controls": [
            {
                "id": "CCF-CMP-01",
                "title": "Internal Audit Program",
                "description": "The organization maintains an internal audit program that independently assesses the design and operating effectiveness of security controls. Internal audits are conducted on a risk-based schedule, cover key control areas, and result in findings and recommendations tracked to remediation.",
                "objective": "Provide independent assurance of control effectiveness and identify improvement areas.",
                "control_type": "Administrative",
                "frequency": "Annual audit plan; audits per schedule; continuous monitoring where automated",
                "mappings": {
                    "soc2": ["CC4.1", "CC4.2"],
                    "iso27001": ["A.5.35", "A.5.36"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-02"],
                    "nist_800_53": ["CA-2", "CA-7"],
                    "pci_dss": ["12.4.2"],
                    "hipaa": ["§164.308(a)(8)"],
                    "gdpr": ["Art. 5(2)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CMP-02",
                "title": "External Audit and Certification Management",
                "description": "The organization manages external audits and certifications (e.g., SOC 2, ISO 27001, PCI DSS) through structured audit preparation, evidence collection, auditor coordination, and findings remediation. Audit reports and certifications are maintained current and provided to customers and stakeholders as appropriate.",
                "objective": "Obtain and maintain external assurance of the security program through independent audits.",
                "control_type": "Administrative",
                "frequency": "Annual (per certification cycle); continuous evidence readiness",
                "mappings": {
                    "soc2": ["CC4.1"],
                    "iso27001": ["A.5.35"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-02"],
                    "nist_800_53": ["CA-2", "CA-6"],
                    "pci_dss": ["12.4.1"],
                    "hipaa": ["§164.308(a)(8)"],
                    "gdpr": ["Art. 42"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CMP-03",
                "title": "Control Exception and Remediation Management",
                "description": "The organization maintains a formal process for managing control exceptions, audit findings, and remediation activities. Exceptions require documented business justification, compensating controls, risk acceptance, and time-bound expiration. Remediation is tracked, assigned owners, and reported to leadership.",
                "objective": "Ensure control gaps are formally managed, tracked, and resolved.",
                "control_type": "Administrative",
                "frequency": "Per occurrence; monthly remediation tracking; quarterly leadership reporting",
                "mappings": {
                    "soc2": ["CC4.2", "CC5.3"],
                    "iso27001": ["A.5.35", "A.5.36"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-03"],
                    "nist_800_53": ["CA-5", "PM-4"],
                    "pci_dss": ["12.4.2.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(B)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CMP-04",
                "title": "Continuous Control Monitoring",
                "description": "The organization implements automated monitoring to continuously assess control effectiveness, detect deviations, and generate evidence. Monitoring covers key technical controls such as access configurations, encryption status, logging coverage, and vulnerability management. Dashboard and metrics provide real-time visibility into compliance posture.",
                "objective": "Move from point-in-time audit evidence to continuous assurance of control effectiveness.",
                "control_type": "Technical",
                "frequency": "Continuous; dashboard updated in real-time; monthly posture review",
                "mappings": {
                    "soc2": ["CC4.1", "CC4.2"],
                    "iso27001": ["A.5.36"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-01", "DE.CM-01"],
                    "nist_800_53": ["CA-7", "PM-31"],
                    "pci_dss": ["10.7", "12.4.2"],
                    "hipaa": ["§164.308(a)(8)"],
                    "gdpr": ["Art. 32(1)(d)"],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: EDP - Endpoint Security
    # =========================================================================
    {
        "id": "EDP",
        "name": "Endpoint Security",
        "description": "Controls governing the security of endpoint devices including laptops, workstations, and mobile devices used by organizational personnel.",
        "controls": [
            {
                "id": "CCF-EDP-01",
                "title": "Endpoint Protection and Management",
                "description": "The organization deploys mobile device management (MDM) or unified endpoint management (UEM) on all corporate endpoints. Managed endpoints enforce security configurations including disk encryption, screen lock, OS auto-update, and firewall enablement. Unmanaged endpoints are restricted from accessing sensitive corporate resources.",
                "objective": "Ensure all endpoints meet minimum security requirements before accessing corporate data.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; monthly compliance reporting",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.8"],
                    "iso27001": ["A.8.1"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.IR-01"],
                    "nist_800_53": ["CM-6", "SC-28"],
                    "pci_dss": ["5.2", "9.5"],
                    "hipaa": ["§164.310(c)", "§164.312(a)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-EDP-02",
                "title": "Endpoint Data Encryption",
                "description": "All organizational endpoints enforce full-disk encryption using approved algorithms. Encryption keys are managed through the endpoint management platform. Encryption status is verified and non-compliant devices are flagged or blocked from corporate access.",
                "objective": "Protect data on endpoint devices from unauthorized access in the event of loss or theft.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; automated compliance checking",
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["SC-28"],
                    "pci_dss": ["3.5.1"],
                    "hipaa": ["§164.312(a)(2)(iv)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-EDP-03",
                "title": "Mobile Device Security",
                "description": "The organization implements security controls for mobile devices used to access corporate data including enrollment in MDM, enforcement of device passcode, remote wipe capability, and containerization of corporate data. BYOD policies are defined and enforced where applicable.",
                "objective": "Secure mobile access to corporate data while supporting workforce flexibility.",
                "control_type": "Technical",
                "frequency": "Continuous; annual BYOD policy review",
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.8.1"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["AC-19"],
                    "pci_dss": [],
                    "hipaa": ["§164.310(c)", "§164.312(d)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            }
        ]
    }
]


# =============================================================================
# OUTPUT GENERATION
# =============================================================================

def build_ccf():
    """Build the full CCF structure."""
    return {
        "metadata": METADATA,
        "domains": DOMAINS
    }


def write_json(ccf, output_path):
    """Write CCF to JSON."""
    with open(output_path, 'w') as f:
        json.dump(ccf, f, indent=2)
    print(f"JSON written to {output_path}")


def write_csv(ccf, output_path):
    """Write CCF to CSV with flattened mappings."""
    frameworks = list(METADATA["frameworks"].keys())
    
    headers = [
        "domain_id", "domain_name", "control_id", "title", "description",
        "objective", "control_type", "frequency"
    ] + [f"mapping_{fw}" for fw in frameworks]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for domain in ccf["domains"]:
            for control in domain["controls"]:
                row = [
                    domain["id"],
                    domain["name"],
                    control["id"],
                    control["title"],
                    control["description"],
                    control["objective"],
                    control["control_type"],
                    control["frequency"]
                ]
                for fw in frameworks:
                    mappings = control.get("mappings", {}).get(fw, [])
                    row.append("; ".join(mappings))
                writer.writerow(row)
    
    print(f"CSV written to {output_path}")


def print_stats(ccf):
    """Print CCF statistics."""
    total_controls = sum(len(d["controls"]) for d in ccf["domains"])
    total_domains = len(ccf["domains"])
    frameworks = list(METADATA["frameworks"].keys())
    
    print(f"\n{'='*60}")
    print(f"OpenCCF v{METADATA['version']} - Build Statistics")
    print(f"{'='*60}")
    print(f"Total Domains:    {total_domains}")
    print(f"Total Controls:   {total_controls}")
    print(f"Frameworks Mapped: {len(frameworks)}")
    print(f"Frameworks: {', '.join(frameworks)}")
    print(f"\nDomain Breakdown:")
    for domain in ccf["domains"]:
        ctrl_count = len(domain["controls"])
        print(f"  {domain['id']:5s} - {domain['name']:45s} [{ctrl_count:3d} controls]")
    
    # Calculate total mappings
    total_mappings = 0
    for domain in ccf["domains"]:
        for control in domain["controls"]:
            for fw in frameworks:
                total_mappings += len(control.get("mappings", {}).get(fw, []))
    print(f"\nTotal Cross-Framework Mappings: {total_mappings}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    output_dir = "/mnt/user-data/outputs"
    os.makedirs(output_dir, exist_ok=True)
    
    ccf = build_ccf()
    print_stats(ccf)
    
    write_json(ccf, os.path.join(output_dir, "openccf.json"))
    write_csv(ccf, os.path.join(output_dir, "openccf.csv"))
    
    print("Generation complete.")