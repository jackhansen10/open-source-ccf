#!/usr/bin/env python3
"""
Open Common Controls Framework (OpenCCF) - FedRAMP High / Government Edition
Extends the commercial CCF baseline with controls required for FedRAMP High
authorization, including NIST 800-53 Rev 5 High baseline coverage and
FedRAMP-specific additional requirements.
"""

import json
import csv
import os
from datetime import date

# =============================================================================
# METADATA
# =============================================================================
METADATA = {
    "name": "Open Common Controls Framework — FedRAMP / Government Edition",
    "version": "1.0.0",
    "license": "Apache-2.0",
    "last_updated": date.today().isoformat(),
    "repository": "https://github.com/jackhansen10/open-source-ccf",
    "base_profile": "OpenCCF Commercial v1.0.0",
    "description": (
        "An extended Common Controls Framework designed for SaaS companies pursuing "
        "FedRAMP High authorization. Builds on the commercial OpenCCF baseline with "
        "additional controls required by NIST 800-53 Rev 5 High baseline and "
        "FedRAMP-specific requirements. Controls marked with fedramp_delta=true are "
        "additions or material enhancements beyond the commercial baseline."
    ),
    "frameworks": {
        "soc2": {
            "name": "SOC 2 Trust Services Criteria",
            "version": "2017 (with 2022 points of focus updates)",
            "publisher": "AICPA"
        },
        "iso27001": {
            "name": "ISO/IEC 27001:2022 Annex A",
            "version": "2022",
            "publisher": "ISO/IEC"
        },
        "iso27017": {
            "name": "ISO/IEC 27017:2015",
            "version": "2015",
            "publisher": "ISO/IEC"
        },
        "iso27018": {
            "name": "ISO/IEC 27018:2019",
            "version": "2019",
            "publisher": "ISO/IEC"
        },
        "nist_csf": {
            "name": "NIST Cybersecurity Framework",
            "version": "2.0",
            "publisher": "NIST"
        },
        "nist_800_53": {
            "name": "NIST SP 800-53",
            "version": "Revision 5 — High Baseline",
            "publisher": "NIST"
        },
        "fedramp": {
            "name": "FedRAMP",
            "version": "High Baseline (Rev 5)",
            "publisher": "FedRAMP PMO / GSA",
            "note": "FedRAMP-specific additional requirements and parameter values beyond NIST 800-53"
        },
        "pci_dss": {
            "name": "PCI DSS",
            "version": "4.0",
            "publisher": "PCI SSC"
        },
        "hipaa": {
            "name": "HIPAA Security Rule",
            "version": "45 CFR Part 164",
            "publisher": "HHS"
        },
        "gdpr": {
            "name": "General Data Protection Regulation",
            "version": "Regulation (EU) 2016/679",
            "publisher": "European Parliament"
        },
        "ccpa": {
            "name": "CCPA / CPRA",
            "version": "California Civil Code §1798.100-199.100",
            "publisher": "State of California"
        }
    }
}

# =============================================================================
# DOMAIN AND CONTROL DEFINITIONS
# =============================================================================
# Controls carry a "fedramp_delta" field:
#   - false = exists in commercial baseline (may have enhanced mappings)
#   - true  = new control or materially enhanced for FedRAMP High
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
                "description": "The organization establishes, approves, and communicates a formal information security policy that defines the organization's commitment to security, assigns accountability, and sets the strategic direction for the security program. The policy is reviewed at least annually and updated as needed. The policy addresses all NIST 800-53 control families and FedRAMP requirements.",
                "objective": "Ensure a management-approved security policy exists, is communicated, and remains current.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon significant change",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.1", "CC1.2"],
                    "iso27001": ["A.5.1"],
                    "iso27017": ["5.1.1"],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01", "GV.PO-02"],
                    "nist_800_53": ["PL-1", "PM-1"],
                    "fedramp": ["PL-1"],
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
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.2", "CC1.3"],
                    "iso27001": ["A.5.2", "A.5.4"],
                    "iso27017": ["6.1.1"],
                    "iso27018": [],
                    "nist_csf": ["GV.RR-01", "GV.RR-02"],
                    "nist_800_53": ["PL-1", "PM-2", "PM-13"],
                    "fedramp": ["PM-2", "PM-13"],
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
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.2", "CC4.1", "CC4.2"],
                    "iso27001": ["A.5.1", "A.5.4"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-01", "GV.OV-02", "GV.OV-03"],
                    "nist_800_53": ["PM-1", "PM-6"],
                    "fedramp": ["PM-1", "PM-6"],
                    "pci_dss": ["12.4", "12.4.1"],
                    "hipaa": ["§164.308(a)(2)"],
                    "gdpr": ["Art. 24"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-04",
                "title": "Acceptable Use Policy",
                "description": "The organization defines and communicates an acceptable use policy that governs the appropriate use of organizational assets, systems, and data. The policy covers personal use, prohibited activities, and consequences for violations.",
                "objective": "Establish clear expectations for appropriate use of organizational resources.",
                "control_type": "Administrative",
                "frequency": "Annual review; acknowledgment at hire and annually",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.1", "CC1.4"],
                    "iso27001": ["A.5.10"],
                    "iso27017": ["8.1.3"],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PL-4"],
                    "fedramp": ["PL-4"],
                    "pci_dss": ["12.3"],
                    "hipaa": ["§164.310(b)", "§164.312(a)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-05",
                "title": "Code of Conduct and Ethics",
                "description": "The organization maintains a code of conduct that establishes ethical expectations and behavioral standards for all personnel. Adherence is required as a condition of employment/engagement.",
                "objective": "Set ethical expectations and create accountability for organizational conduct.",
                "control_type": "Administrative",
                "frequency": "Annual acknowledgment; review upon significant change",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.1", "CC1.4", "CC1.5"],
                    "iso27001": ["A.5.4", "A.6.2"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PL-4", "PS-8"],
                    "fedramp": ["PL-4", "PS-8"],
                    "pci_dss": ["12.6.3.2"],
                    "hipaa": ["§164.308(a)(1)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-06",
                "title": "Regulatory and Contractual Compliance Management",
                "description": "The organization identifies, tracks, and maintains compliance with applicable legal, regulatory, and contractual requirements including federal requirements. A compliance register is maintained and reviewed regularly.",
                "objective": "Ensure the organization meets all applicable external obligations.",
                "control_type": "Administrative",
                "frequency": "Continuous; formal review quarterly",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC2.3", "CC3.1"],
                    "iso27001": ["A.5.31", "A.5.32", "A.5.33", "A.5.34"],
                    "iso27017": [],
                    "iso27018": ["A.18.1.4"],
                    "nist_csf": ["GV.OC-02", "GV.OC-03"],
                    "nist_800_53": ["CA-2", "PM-10"],
                    "fedramp": ["CA-2", "PM-10"],
                    "pci_dss": ["12.1.1", "12.4.2"],
                    "hipaa": ["§164.316(b)(2)(iii)"],
                    "gdpr": ["Art. 24", "Art. 5(2)"],
                    "ccpa": ["§1798.185"]
                }
            },
            {
                "id": "CCF-GOV-07",
                "title": "System Security Plan (SSP)",
                "description": "The organization develops and maintains a System Security Plan (SSP) that describes the system authorization boundary, system architecture and data flows, interconnections, security categorization, and the implementation status of each applicable security control. The SSP is reviewed and updated at least annually and whenever significant changes occur.",
                "objective": "Provide a comprehensive security description of the system for authorizing officials and assessors.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon significant system changes",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC2.1"],
                    "iso27001": ["A.5.1"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PL-2", "PL-2(3)"],
                    "fedramp": ["PL-2", "FedRAMP SSP Template"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-08",
                "title": "System Use Notification (Login Banners)",
                "description": "The organization displays an approved system use notification message or banner before granting access to the system. The notification states that usage may be monitored, recorded, and subject to audit; that unauthorized use is prohibited and subject to criminal and civil penalties; and that use of the system indicates consent to monitoring.",
                "objective": "Notify users of monitoring and establish legal basis for enforcement.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual banner text review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.8.5"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01"],
                    "nist_800_53": ["AC-8"],
                    "fedramp": ["AC-8"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-GOV-09",
                "title": "Security Planning and Rules of Behavior",
                "description": "The organization establishes rules of behavior that describe expected behavior and responsibilities for information system usage. Users acknowledge rules of behavior before being granted access. Rules cover acceptable use, data handling, social media, mobile devices, and consequences for non-compliance.",
                "objective": "Establish explicit user responsibilities as a condition of system access.",
                "control_type": "Administrative",
                "frequency": "At onboarding; annual re-acknowledgment",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC1.4"],
                    "iso27001": ["A.5.10"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.PO-01"],
                    "nist_800_53": ["PL-4"],
                    "fedramp": ["PL-4", "PL-4(1)"],
                    "pci_dss": ["12.3"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
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
        "description": "Defines the processes for identifying, analyzing, evaluating, treating, and monitoring information security risks.",
        "controls": [
            {
                "id": "CCF-RSK-01",
                "title": "Risk Management Program",
                "description": "The organization establishes and maintains a formal risk management program aligned with NIST SP 800-37 and NIST SP 800-39 that defines the methodology, scope, frequency, and criteria for information security risk assessments. The program is aligned with organizational objectives, risk appetite, and federal risk management requirements.",
                "objective": "Provide a systematic approach to identifying and managing information security risks.",
                "control_type": "Administrative",
                "frequency": "Annual program review; continuous risk identification",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC3.1", "CC3.2"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.RM-01", "GV.RM-02", "ID.RA-01"],
                    "nist_800_53": ["RA-1", "RA-2", "PM-9", "PM-28"],
                    "fedramp": ["RA-1", "RA-2", "PM-9", "PM-28"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(2)", "Art. 35"],
                    "ccpa": ["§1798.100(e)"]
                }
            },
            {
                "id": "CCF-RSK-02",
                "title": "Risk Assessment Execution",
                "description": "The organization performs comprehensive risk assessments at least annually and upon significant changes. Assessments identify threats, vulnerabilities, likelihood, and impact. For FedRAMP, risk assessments follow NIST SP 800-30 methodology and include assessment of the full authorization boundary.",
                "objective": "Identify and evaluate current security risks based on the threat environment.",
                "control_type": "Administrative",
                "frequency": "Annual; upon significant change; new projects/systems",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC3.2", "CC3.3"],
                    "iso27001": ["A.5.8", "A.8.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-01", "ID.RA-02", "ID.RA-03"],
                    "nist_800_53": ["RA-3", "RA-3(1)", "RA-5"],
                    "fedramp": ["RA-3", "RA-3(1)"],
                    "pci_dss": ["6.3.1", "12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(2)", "Art. 35(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-03",
                "title": "Risk Treatment and Mitigation",
                "description": "The organization defines and implements risk treatment plans for identified risks. Treatment options include mitigation, transfer, acceptance, and avoidance. Risk owners are assigned and accountable for implementation.",
                "objective": "Ensure identified risks are addressed through appropriate treatment actions.",
                "control_type": "Administrative",
                "frequency": "Ongoing; reviewed quarterly",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC3.3", "CC3.4", "CC5.1"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-05", "ID.RA-06"],
                    "nist_800_53": ["RA-7", "PM-4"],
                    "fedramp": ["RA-7", "PM-4"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(B)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-04",
                "title": "Risk Register Maintenance",
                "description": "The organization maintains a risk register documenting identified risks, risk ratings, risk owners, treatment decisions, and residual risk. The register is reviewed quarterly and upon identification of new material risks.",
                "objective": "Maintain a centralized, current view of the organization's risk posture.",
                "control_type": "Administrative",
                "frequency": "Quarterly update; continuous intake",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC3.2", "CC3.4", "CC4.1"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-04", "GV.RM-05"],
                    "nist_800_53": ["PM-4", "RA-3"],
                    "fedramp": ["PM-4"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 32(2)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-05",
                "title": "Risk Acceptance",
                "description": "The organization maintains a formal risk acceptance process requiring documented approval from the authorizing official (AO) or designated representative for risks that exceed tolerance levels. Accepted risks are tracked in the POA&M and periodically re-evaluated.",
                "objective": "Ensure residual risks are consciously accepted by accountable individuals.",
                "control_type": "Administrative",
                "frequency": "Per occurrence; annual re-evaluation",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC3.4", "CC5.3"],
                    "iso27001": ["A.5.8"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.RM-06", "GV.RM-07"],
                    "nist_800_53": ["PM-9", "CA-5", "CA-6"],
                    "fedramp": ["CA-5", "CA-6"],
                    "pci_dss": ["12.3.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(B)"],
                    "gdpr": ["Art. 32"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-06",
                "title": "Threat Intelligence",
                "description": "The organization collects, analyzes, and acts upon threat intelligence relevant to its industry, technology stack, and threat profile. Threat intelligence feeds include government sources (CISA, US-CERT) and are used to inform risk assessments and security monitoring.",
                "objective": "Maintain awareness of the current threat landscape to proactively manage risk.",
                "control_type": "Operational",
                "frequency": "Continuous",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC3.1", "CC7.2"],
                    "iso27001": ["A.5.7"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.RA-02"],
                    "nist_800_53": ["PM-16", "RA-3", "SI-5", "RA-10"],
                    "fedramp": ["PM-16", "SI-5", "RA-10"],
                    "pci_dss": ["6.3.1"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-07",
                "title": "Security Categorization (FIPS 199)",
                "description": "The organization categorizes the information system and the information processed, stored, and transmitted by the system in accordance with FIPS 199. The security categorization considers the potential impact on organizational operations, organizational assets, individuals, other organizations, and the Nation. Categorization is documented in the SSP and validated by the AO.",
                "objective": "Establish the security impact level that drives control selection and implementation rigor.",
                "control_type": "Administrative",
                "frequency": "At system inception; reviewed annually; updated upon significant change",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": [],
                    "iso27001": ["A.5.12"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["ID.AM-05"],
                    "nist_800_53": ["RA-2"],
                    "fedramp": ["RA-2", "FIPS 199", "FIPS 200"],
                    "pci_dss": [],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-RSK-08",
                "title": "Authorization to Operate (ATO)",
                "description": "The organization obtains and maintains an authorization to operate (ATO) from the designated authorizing official (AO) prior to placing the system into operation. The authorization is based on a comprehensive security assessment and acceptance of residual risk. The ATO is reauthorized per FedRAMP continuous monitoring requirements.",
                "objective": "Obtain formal risk acceptance and operational authorization from the responsible authority.",
                "control_type": "Administrative",
                "frequency": "Initial authorization; continuous monitoring; annual ATO review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": [],
                    "iso27001": [],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.OV-01"],
                    "nist_800_53": ["CA-6", "CA-6(1)"],
                    "fedramp": ["CA-6", "FedRAMP Authorization Process"],
                    "pci_dss": [],
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
        "description": "Controls ensuring security considerations are integrated into employment lifecycle processes.",
        "controls": [
            {
                "id": "CCF-HRS-01",
                "title": "Personnel Screening",
                "description": "The organization screens individuals prior to authorizing access to the information system. Screening is commensurate with the position risk designation and includes, at minimum, national agency checks. For FedRAMP High, personnel with access to federal data must undergo background investigation consistent with the position sensitivity level per OPM guidance.",
                "objective": "Verify the trustworthiness of personnel commensurate with their access level and position risk.",
                "control_type": "Administrative",
                "frequency": "Prior to access; rescreening per position sensitivity (minimum every 5 years)",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC1.4"],
                    "iso27001": ["A.6.1"],
                    "iso27017": [],
                    "iso27018": ["A.11.4"],
                    "nist_csf": ["PR.IP-11"],
                    "nist_800_53": ["PS-3", "PS-3(3)"],
                    "fedramp": ["PS-3", "PS-3(3)", "FedRAMP High: Position Sensitivity"],
                    "pci_dss": ["12.7", "12.7.1"],
                    "hipaa": ["§164.308(a)(3)(ii)(B)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-02",
                "title": "Confidentiality and Security Agreements",
                "description": "Personnel and relevant third parties sign confidentiality (NDA) and security obligation agreements as a condition of access. Agreements cover data handling, acceptable use, and post-employment obligations.",
                "objective": "Establish binding security and confidentiality obligations for all personnel.",
                "control_type": "Administrative",
                "frequency": "At hire/engagement; upon material policy change",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.4", "CC1.5"],
                    "iso27001": ["A.6.2", "A.5.14"],
                    "iso27017": ["6.1.2"],
                    "iso27018": ["A.6.1.2"],
                    "nist_csf": ["PR.IP-11"],
                    "nist_800_53": ["PS-6", "PL-4"],
                    "fedramp": ["PS-6", "PL-4"],
                    "pci_dss": ["12.8.2"],
                    "hipaa": ["§164.308(a)(4)(ii)(B)", "§164.314(a)(2)"],
                    "gdpr": ["Art. 28(3)", "Art. 38(5)"],
                    "ccpa": ["§1798.140(w)"]
                }
            },
            {
                "id": "CCF-HRS-03",
                "title": "Security Awareness Training",
                "description": "The organization provides role-based security awareness training to all personnel upon hire and at least annually. Training covers security policies, phishing, social engineering, data handling, and incident reporting. Specialized training is provided for personnel with significant security responsibilities. Training content is updated to reflect current threats.",
                "objective": "Ensure all personnel understand their security responsibilities.",
                "control_type": "Administrative",
                "frequency": "At onboarding; annual refresher; role-based as needed",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.4", "CC2.2"],
                    "iso27001": ["A.6.3"],
                    "iso27017": ["7.2.2"],
                    "iso27018": ["A.7.2.2"],
                    "nist_csf": ["PR.AT-01", "PR.AT-02"],
                    "nist_800_53": ["AT-1", "AT-2", "AT-2(2)", "AT-3", "AT-4"],
                    "fedramp": ["AT-1", "AT-2", "AT-2(2)", "AT-3", "AT-4"],
                    "pci_dss": ["12.6", "12.6.1", "12.6.2"],
                    "hipaa": ["§164.308(a)(5)(i)", "§164.308(a)(5)(ii)(A)"],
                    "gdpr": ["Art. 39(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-04",
                "title": "Disciplinary Process",
                "description": "The organization maintains a formal disciplinary process for personnel who violate security policies, including escalation and consequences proportionate to the violation.",
                "objective": "Deter security policy violations and ensure consistent enforcement.",
                "control_type": "Administrative",
                "frequency": "Per occurrence; annual policy review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC1.5"],
                    "iso27001": ["A.6.4"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": [],
                    "nist_800_53": ["PS-8"],
                    "fedramp": ["PS-8"],
                    "pci_dss": ["12.6.3.2"],
                    "hipaa": ["§164.308(a)(1)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-05",
                "title": "Personnel Offboarding and Termination",
                "description": "The organization implements a formal offboarding process ensuring timely revocation of access upon termination, resignation, or role change. Access is revoked same-day for involuntary termination. The process includes return of assets, revocation of all logical and physical access, and retrieval of authenticators.",
                "objective": "Prevent unauthorized access by former or transitioning personnel.",
                "control_type": "Administrative",
                "frequency": "Per occurrence; same-day for involuntary; within 24 hours for voluntary",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.2", "CC6.5"],
                    "iso27001": ["A.6.5"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["PS-4", "PS-4(2)", "PS-5"],
                    "fedramp": ["PS-4", "PS-4(2)", "PS-5"],
                    "pci_dss": ["8.2.6", "12.7"],
                    "hipaa": ["§164.308(a)(3)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-06",
                "title": "Personnel Transfer",
                "description": "The organization reviews and modifies logical and physical access authorizations when personnel are reassigned or transferred to new positions. Access rights are adjusted within 24 hours to reflect new role requirements and remove access no longer needed.",
                "objective": "Ensure access remains appropriate when personnel change roles within the organization.",
                "control_type": "Administrative",
                "frequency": "Per transfer event; within 24 hours",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.2"],
                    "iso27001": ["A.5.18"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["PS-5"],
                    "fedramp": ["PS-5"],
                    "pci_dss": ["7.2.4"],
                    "hipaa": ["§164.308(a)(3)(ii)(B)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-HRS-07",
                "title": "Third-Party Personnel Security",
                "description": "The organization ensures third-party providers (contractors, MSPs, subprocessors) comply with personnel security requirements including screening, training, and access termination equivalent to those applied to organizational employees, commensurate with access level.",
                "objective": "Extend personnel security controls to non-employee personnel with system access.",
                "control_type": "Administrative",
                "frequency": "At engagement; annual verification; upon contract change",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC9.2"],
                    "iso27001": ["A.5.19", "A.5.20"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["GV.SC-05"],
                    "nist_800_53": ["PS-7"],
                    "fedramp": ["PS-7"],
                    "pci_dss": ["12.8"],
                    "hipaa": ["§164.308(b)(1)"],
                    "gdpr": ["Art. 28(3)"],
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
        "description": "Controls for identifying, classifying, and managing organizational assets.",
        "controls": [
            {
                "id": "CCF-AAM-01",
                "title": "Asset Inventory",
                "description": "The organization maintains a complete and accurate inventory of information assets including hardware, software, cloud resources, and data stores. Asset ownership is assigned and the inventory is updated continuously or quarterly.",
                "objective": "Maintain visibility into all organizational assets.",
                "control_type": "Operational",
                "frequency": "Continuous (automated); quarterly manual review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.5.9", "A.5.10", "A.5.11"],
                    "iso27017": ["8.1.1"],
                    "iso27018": [],
                    "nist_csf": ["ID.AM-01", "ID.AM-02"],
                    "nist_800_53": ["CM-8", "CM-8(1)", "CM-8(2)", "CM-8(3)", "PM-5"],
                    "fedramp": ["CM-8", "CM-8(1)", "CM-8(2)", "CM-8(3)"],
                    "pci_dss": ["9.5.1", "12.5.1"],
                    "hipaa": ["§164.310(d)(1)"],
                    "gdpr": ["Art. 30"],
                    "ccpa": ["§1798.100(a)"]
                }
            },
            {
                "id": "CCF-AAM-02",
                "title": "Data Classification",
                "description": "The organization implements a data classification scheme that categorizes data based on sensitivity, regulatory requirements, and business value. Classification levels drive handling, storage, and transmission requirements.",
                "objective": "Enable appropriate protection of data based on its sensitivity.",
                "control_type": "Administrative",
                "frequency": "At data creation; reviewed annually",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "C1.1"],
                    "iso27001": ["A.5.12", "A.5.13"],
                    "iso27017": ["8.2.2"],
                    "iso27018": ["A.10.1"],
                    "nist_csf": ["ID.AM-05"],
                    "nist_800_53": ["RA-2", "SC-16"],
                    "fedramp": ["RA-2"],
                    "pci_dss": ["9.4.1"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 9", "Art. 10"],
                    "ccpa": ["§1798.140(v)"]
                }
            },
            {
                "id": "CCF-AAM-03",
                "title": "Media and Asset Disposal",
                "description": "The organization implements procedures for secure disposal and destruction of media and assets containing sensitive data. Methods are commensurate with data classification and NIST SP 800-88 guidelines. Disposal includes verification of destruction.",
                "objective": "Prevent unauthorized disclosure through improper asset disposal.",
                "control_type": "Operational",
                "frequency": "Per occurrence; annual process review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.5"],
                    "iso27001": ["A.7.10", "A.7.14", "A.8.10"],
                    "iso27017": [],
                    "iso27018": ["A.9.4.2"],
                    "nist_csf": ["PR.DS-03"],
                    "nist_800_53": ["MP-6", "MP-6(1)", "MP-6(2)", "PE-16"],
                    "fedramp": ["MP-6", "MP-6(1)", "MP-6(2)", "NIST SP 800-88"],
                    "pci_dss": ["9.4.5", "9.4.6", "9.4.7"],
                    "hipaa": ["§164.310(d)(2)(i)", "§164.310(d)(2)(ii)"],
                    "gdpr": ["Art. 17"],
                    "ccpa": ["§1798.105"]
                }
            },
            {
                "id": "CCF-AAM-04",
                "title": "Cloud Resource Management",
                "description": "The organization maintains an inventory and governance process for cloud resources including IaaS, PaaS, and SaaS. Cloud resource provisioning follows approved architecture patterns and is subject to configuration management and tagging standards.",
                "objective": "Ensure cloud resources are inventoried, governed, and secured.",
                "control_type": "Operational",
                "frequency": "Continuous (automated); monthly review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC7.1"],
                    "iso27001": ["A.5.23"],
                    "iso27017": ["CLD.6.3", "CLD.8.1"],
                    "iso27018": [],
                    "nist_csf": ["ID.AM-02"],
                    "nist_800_53": ["CM-8", "SA-9"],
                    "fedramp": ["CM-8", "SA-9"],
                    "pci_dss": ["2.1.1"],
                    "hipaa": ["§164.308(a)(1)(ii)(A)"],
                    "gdpr": ["Art. 28"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-AAM-05",
                "title": "Media Transport and Storage Protection",
                "description": "The organization protects and controls digital and non-digital media during transport outside of controlled areas. Controls include encryption of digital media, use of tamper-evident packaging for physical media, and use of authorized couriers. Media transport is logged and tracked.",
                "objective": "Prevent unauthorized access, modification, or loss of data during media transport.",
                "control_type": "Operational",
                "frequency": "Per transport event; annual process review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.7"],
                    "iso27001": ["A.7.10"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-02"],
                    "nist_800_53": ["MP-5", "MP-5(4)"],
                    "fedramp": ["MP-5", "MP-5(4)"],
                    "pci_dss": ["9.4"],
                    "hipaa": ["§164.310(d)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-AAM-06",
                "title": "Media Access Restrictions",
                "description": "The organization restricts access to digital and non-digital media containing sensitive information to authorized individuals. Media access controls are commensurate with the sensitivity of the information and include physical and logical restrictions.",
                "objective": "Prevent unauthorized access to information on removable and portable media.",
                "control_type": "Operational",
                "frequency": "Continuous enforcement; quarterly review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.7.10"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["MP-2", "MP-4", "MP-7"],
                    "fedramp": ["MP-2", "MP-4", "MP-7"],
                    "pci_dss": ["9.4.1"],
                    "hipaa": ["§164.310(d)(1)"],
                    "gdpr": [],
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
        "description": "Controls governing user identity lifecycle, authentication, authorization, and access management.",
        "controls": [
            {
                "id": "CCF-IAM-01",
                "title": "Access Control Policy",
                "description": "The organization establishes an access control policy based on least privilege and need-to-know principles. The policy defines access authorization requirements, RBAC standards, and procedures for granting, modifying, and revoking access.",
                "objective": "Establish the foundational policy for controlling access to organizational resources.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon significant change",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.3"],
                    "iso27001": ["A.5.15", "A.8.3"],
                    "iso27017": ["9.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01"],
                    "nist_800_53": ["AC-1", "AC-2", "AC-3"],
                    "fedramp": ["AC-1", "AC-2", "AC-3"],
                    "pci_dss": ["7.1", "7.2"],
                    "hipaa": ["§164.312(a)(1)", "§164.308(a)(4)(i)"],
                    "gdpr": ["Art. 25", "Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-02",
                "title": "User Provisioning and Deprovisioning",
                "description": "The organization implements formal processes for provisioning and deprovisioning user accounts. Provisioning requires documented authorization. Deprovisioning occurs promptly upon role change, transfer, or termination.",
                "objective": "Ensure access is granted only when authorized and removed when no longer needed.",
                "control_type": "Operational",
                "frequency": "Per occurrence; automated where possible",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.2"],
                    "iso27001": ["A.5.16", "A.5.18"],
                    "iso27017": ["9.2.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01", "PR.AA-05"],
                    "nist_800_53": ["AC-2", "AC-2(1)", "AC-2(2)", "AC-2(3)", "AC-2(4)"],
                    "fedramp": ["AC-2", "AC-2(1)", "AC-2(2)", "AC-2(3)", "AC-2(4)"],
                    "pci_dss": ["7.1", "8.2.4", "8.2.5", "8.2.6"],
                    "hipaa": ["§164.308(a)(3)(ii)(A)", "§164.308(a)(3)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-03",
                "title": "Multi-Factor Authentication",
                "description": "The organization requires multi-factor authentication (MFA) for all access to production systems, remote access, administrative interfaces, and cloud consoles. For FedRAMP High, MFA must be phishing-resistant (e.g., PIV, FIDO2) for privileged access and conform to NIST SP 800-63B AAL2 or higher.",
                "objective": "Reduce unauthorized access risk from credential compromise.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual MFA coverage review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.5"],
                    "iso27017": ["9.4.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["IA-2(1)", "IA-2(2)", "IA-2(6)", "IA-2(8)", "IA-2(12)"],
                    "fedramp": ["IA-2(1)", "IA-2(2)", "IA-2(6)", "IA-2(8)", "IA-2(12)", "NIST SP 800-63B"],
                    "pci_dss": ["8.4.1", "8.4.2", "8.4.3"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-04",
                "title": "Privileged Access Management",
                "description": "The organization restricts and monitors privileged (administrative) access. Privileged access uses separate accounts, is subject to enhanced logging, and is reviewed quarterly. Just-in-time (JIT) privileged access is implemented where technically feasible.",
                "objective": "Minimize attack surface from administrative access.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; quarterly privileged account review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.3"],
                    "iso27001": ["A.8.2", "A.8.18"],
                    "iso27017": ["9.2.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["AC-6(1)", "AC-6(2)", "AC-6(5)", "AC-6(7)", "AC-6(9)", "AC-6(10)"],
                    "fedramp": ["AC-6(1)", "AC-6(2)", "AC-6(5)", "AC-6(7)", "AC-6(9)", "AC-6(10)"],
                    "pci_dss": ["7.2.1", "8.6.1"],
                    "hipaa": ["§164.312(a)(1)"],
                    "gdpr": ["Art. 32(1)(b)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-05",
                "title": "Access Reviews",
                "description": "The organization conducts periodic access reviews to validate access rights remain appropriate. Reviews cover standard, privileged, and third-party accounts. Inappropriate access is remediated promptly.",
                "objective": "Detect and remediate access drift and excessive permissions.",
                "control_type": "Operational",
                "frequency": "Quarterly for privileged; semi-annually for standard",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.2", "CC6.3"],
                    "iso27001": ["A.5.18", "A.8.2"],
                    "iso27017": ["9.2.5"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["AC-2(3)", "AC-6(7)"],
                    "fedramp": ["AC-2(3)", "AC-6(7)"],
                    "pci_dss": ["7.2.4", "7.2.5"],
                    "hipaa": ["§164.308(a)(4)(ii)(C)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-06",
                "title": "Password and Credential Management",
                "description": "The organization enforces password and credential management standards including minimum complexity, prohibition of credential sharing, and secure storage using approved hashing algorithms. For FedRAMP, password policies conform to NIST SP 800-63B memorized secret guidelines.",
                "objective": "Ensure credentials are strong, unique, and securely managed.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.5.17", "A.8.5"],
                    "iso27017": ["9.4.3"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["IA-5", "IA-5(1)", "IA-5(2)", "IA-5(6)"],
                    "fedramp": ["IA-5", "IA-5(1)", "IA-5(2)", "IA-5(6)", "NIST SP 800-63B"],
                    "pci_dss": ["8.3.1", "8.3.4", "8.3.6", "8.3.7"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-07",
                "title": "Service Account and API Key Management",
                "description": "The organization manages service accounts, API keys, and machine credentials through formal lifecycle processes. Service accounts are inventoried, assigned owners, granted minimum permissions, and subject to credential rotation.",
                "objective": "Prevent unauthorized access through unmanaged non-human identities.",
                "control_type": "Technical",
                "frequency": "Continuous; quarterly inventory review; rotation per policy",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.3"],
                    "iso27001": ["A.5.16", "A.5.18", "A.8.5"],
                    "iso27017": ["9.2.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-01", "PR.AA-03"],
                    "nist_800_53": ["AC-2", "IA-4", "IA-5"],
                    "fedramp": ["AC-2", "IA-4", "IA-5"],
                    "pci_dss": ["8.6.1", "8.6.2", "8.6.3"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-08",
                "title": "Single Sign-On and Centralized Authentication",
                "description": "The organization implements centralized authentication through SSO integrated with a corporate identity provider. Application access is federated through the IdP.",
                "objective": "Centralize authentication for consistent policy enforcement.",
                "control_type": "Technical",
                "frequency": "Continuous; annual SSO coverage review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.8.5"],
                    "iso27017": ["9.4.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["IA-2", "IA-8"],
                    "fedramp": ["IA-2", "IA-8", "IA-8(1)", "IA-8(2)", "IA-8(4)"],
                    "pci_dss": ["7.2", "8.4"],
                    "hipaa": ["§164.312(d)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-09",
                "title": "Remote Access Security",
                "description": "The organization controls remote access through authorized, encrypted channels. Remote access requires MFA and is logged.",
                "objective": "Secure remote connectivity while maintaining visibility.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.1", "A.6.7"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["AC-17", "AC-17(1)", "AC-17(2)", "AC-17(3)", "AC-17(4)"],
                    "fedramp": ["AC-17", "AC-17(1)", "AC-17(2)", "AC-17(3)", "AC-17(4)"],
                    "pci_dss": ["8.4.3"],
                    "hipaa": ["§164.312(a)(1)", "§164.312(e)(1)"],
                    "gdpr": ["Art. 32(1)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-10",
                "title": "Separation of Duties",
                "description": "The organization defines and enforces separation of duties for critical functions to prevent any single individual from controlling all aspects of a critical process. Duties are divided such that no one person can authorize, execute, and review a sensitive action. Separation is enforced through technical controls (RBAC, workflow approvals) and documented in the SSP.",
                "objective": "Prevent fraud, error, and abuse through mandatory division of critical functions.",
                "control_type": "Administrative",
                "frequency": "Continuous enforcement; annual role/duty matrix review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC5.1", "CC6.1"],
                    "iso27001": ["A.5.3"],
                    "iso27017": ["6.1.2"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-05"],
                    "nist_800_53": ["AC-5"],
                    "fedramp": ["AC-5"],
                    "pci_dss": ["6.5.2"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-11",
                "title": "Session Management",
                "description": "The organization manages user sessions including: (a) limiting concurrent sessions per user per FedRAMP parameter values; (b) enforcing session lock after 15 minutes of inactivity; (c) terminating sessions after conditions are met (e.g., inactivity timeout, session maximum); (d) displaying session lock with pattern-hiding display.",
                "objective": "Prevent unauthorized access through unattended or excessive sessions.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual parameter review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.1"],
                    "iso27001": ["A.8.1"],
                    "iso27017": ["11.2.8"],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["AC-10", "AC-11", "AC-11(1)", "AC-12"],
                    "fedramp": ["AC-10", "AC-11", "AC-11(1)", "AC-12"],
                    "pci_dss": ["8.2.8"],
                    "hipaa": ["§164.312(a)(2)(iii)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-12",
                "title": "Information Flow Enforcement",
                "description": "The organization enforces approved authorizations for controlling the flow of information within the system and between connected systems based on security policy. Information flow controls include boundary protections, data guards, and cross-domain solutions where applicable.",
                "objective": "Ensure information flows only through authorized paths and between authorized entities.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual flow rule review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.6"],
                    "iso27001": ["A.8.22"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-02"],
                    "nist_800_53": ["AC-4", "AC-4(4)"],
                    "fedramp": ["AC-4", "AC-4(4)"],
                    "pci_dss": ["1.3.1"],
                    "hipaa": ["§164.312(e)(1)"],
                    "gdpr": [],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-IAM-13",
                "title": "Wireless Access Restrictions",
                "description": "The organization restricts and monitors wireless access to the information system. Wireless access points are authorized, documented, and configured with encryption (WPA3 or WPA2-Enterprise minimum). Rogue wireless access point detection is implemented. Guest wireless is segmented from production networks.",
                "objective": "Prevent unauthorized network access through wireless attack vectors.",
                "control_type": "Technical",
                "frequency": "Continuous; quarterly wireless scan; annual policy review",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.6"],
                    "iso27001": ["A.8.20"],
                    "iso27017": [],
                    "iso27018": [],
                    "nist_csf": ["PR.AA-03"],
                    "nist_800_53": ["AC-18", "AC-18(1)", "AC-18(4)", "AC-18(5)"],
                    "fedramp": ["AC-18", "AC-18(1)", "AC-18(4)", "AC-18(5)"],
                    "pci_dss": ["11.2.1"],
                    "hipaa": [],
                    "gdpr": [],
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
        "description": "Controls governing cryptographic techniques and key management. FedRAMP requires FIPS 140-2/3 validated cryptographic modules.",
        "controls": [
            {
                "id": "CCF-CRY-01",
                "title": "Cryptographic Policy and FIPS Validation",
                "description": "The organization establishes a cryptographic policy requiring the use of FIPS 140-2 (or FIPS 140-3) validated cryptographic modules for all encryption operations protecting federal data. The policy defines approved algorithms, key lengths, and use cases. Non-validated modules are prohibited for federal workloads.",
                "objective": "Ensure all cryptographic protections meet federal validation requirements.",
                "control_type": "Administrative",
                "frequency": "Annual review; update upon cryptographic vulnerability disclosure",
                "fedramp_delta": True,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1"],
                    "iso27018": ["A.10.1.2"],
                    "nist_csf": ["PR.DS-01", "PR.DS-02"],
                    "nist_800_53": ["SC-13"],
                    "fedramp": ["SC-13", "FIPS 140-2", "FIPS 140-3"],
                    "pci_dss": ["3.6.1", "4.2.1"],
                    "hipaa": ["§164.312(a)(2)(iv)", "§164.312(e)(2)(ii)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": ["§1798.150(a)"]
                }
            },
            {
                "id": "CCF-CRY-02",
                "title": "Encryption at Rest",
                "description": "The organization encrypts sensitive data at rest using FIPS-validated modules and approved algorithms (e.g., AES-256) across all storage systems. Encryption is enforced by default for all environments containing production or federal data.",
                "objective": "Protect stored data from unauthorized disclosure.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual configuration review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7", "C1.1"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1"],
                    "iso27018": ["A.11.6"],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["SC-28", "SC-28(1)"],
                    "fedramp": ["SC-28", "SC-28(1)"],
                    "pci_dss": ["3.5.1", "3.5.1.1"],
                    "hipaa": ["§164.312(a)(2)(iv)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": ["§1798.150(a)"]
                }
            },
            {
                "id": "CCF-CRY-03",
                "title": "Encryption in Transit",
                "description": "The organization encrypts data in transit using FIPS-validated modules and approved protocols (TLS 1.2+ with FIPS-approved cipher suites). Unencrypted transmission of sensitive data is prohibited. Certificate validation is enforced.",
                "objective": "Protect data from interception or tampering during transmission.",
                "control_type": "Technical",
                "frequency": "Continuous enforcement; annual protocol review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7", "C1.1"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1", "13.1.1"],
                    "iso27018": ["A.13.1.1"],
                    "nist_csf": ["PR.DS-02"],
                    "nist_800_53": ["SC-8", "SC-8(1)", "SC-23"],
                    "fedramp": ["SC-8", "SC-8(1)", "SC-23"],
                    "pci_dss": ["4.2.1", "4.2.1.1"],
                    "hipaa": ["§164.312(e)(1)", "§164.312(e)(2)(ii)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CRY-04",
                "title": "Cryptographic Key Management",
                "description": "The organization implements key management covering generation, distribution, storage, rotation, revocation, and destruction. Keys are generated using FIPS-approved random number generators, stored in FIPS-validated KMS/HSM, and rotated per defined schedules.",
                "objective": "Ensure cryptographic keys are securely managed throughout their lifecycle.",
                "control_type": "Technical",
                "frequency": "Continuous; rotation per policy; annual review",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.1", "CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.2"],
                    "iso27018": ["A.10.1.2"],
                    "nist_csf": ["PR.DS-01"],
                    "nist_800_53": ["SC-12", "SC-12(1)"],
                    "fedramp": ["SC-12", "SC-12(1)"],
                    "pci_dss": ["3.6.1", "3.7.1", "3.7.2", "3.7.3", "3.7.4"],
                    "hipaa": ["§164.312(a)(2)(iv)"],
                    "gdpr": ["Art. 32(1)(a)"],
                    "ccpa": []
                }
            },
            {
                "id": "CCF-CRY-05",
                "title": "Certificate Management",
                "description": "The organization maintains an inventory of TLS/SSL and digital certificates, monitors expiration, and ensures timely renewal. Certificates use approved key lengths and algorithms.",
                "objective": "Prevent service disruptions from expired or misconfigured certificates.",
                "control_type": "Operational",
                "frequency": "Continuous monitoring; automated renewal where possible",
                "fedramp_delta": False,
                "mappings": {
                    "soc2": ["CC6.7"],
                    "iso27001": ["A.8.24"],
                    "iso27017": ["10.1.1"],
                    "iso27018": [],
                    "nist_csf": ["PR.DS-02"],
                    "nist_800_53": ["SC-17"],
                    "fedramp": ["SC-17"],
                    "pci_dss": ["4.2.1"],
                    "hipaa": [],
                    "gdpr": [],
                    "ccpa": []
                }
            }
        ]
    },

    # =========================================================================
    # DOMAIN: PHY - Physical Security (same as commercial, no delta)
    # =========================================================================
    {
        "id": "PHY",
        "name": "Physical Security",
        "description": "Controls protecting physical facilities, equipment, and infrastructure.",
        "controls": [
            {"id": "CCF-PHY-01", "title": "Physical Access Controls", "description": "The organization restricts physical access to facilities, data centers, and sensitive areas to authorized personnel. Access control mechanisms include badge systems, biometric readers, and key management.", "objective": "Prevent unauthorized physical access.", "control_type": "Physical", "frequency": "Continuous enforcement; quarterly access list review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.4"], "iso27001": ["A.7.1", "A.7.2", "A.7.3"], "iso27017": ["11.1.1"], "iso27018": [], "nist_csf": ["PR.AA-02"], "nist_800_53": ["PE-2", "PE-3", "PE-3(1)", "PE-6", "PE-6(1)"], "fedramp": ["PE-2", "PE-3", "PE-3(1)", "PE-6", "PE-6(1)"], "pci_dss": ["9.2", "9.3"], "hipaa": ["§164.310(a)(1)", "§164.310(a)(2)(ii)"], "gdpr": ["Art. 32(1)(b)"], "ccpa": []}},
            {"id": "CCF-PHY-02", "title": "Visitor Management", "description": "The organization maintains visitor management including registration, identification, escort requirements, and log maintenance.", "objective": "Control and document visitor access.", "control_type": "Physical", "frequency": "Per occurrence; monthly log review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.4"], "iso27001": ["A.7.2"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.AA-02"], "nist_800_53": ["PE-8", "PE-8(1)"], "fedramp": ["PE-8", "PE-8(1)"], "pci_dss": ["9.3.1", "9.3.2"], "hipaa": ["§164.310(a)(2)(iii)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-PHY-03", "title": "Environmental Controls", "description": "The organization implements environmental protections including fire detection/suppression, HVAC, water detection, and UPS. Systems are monitored and tested.", "objective": "Protect systems from environmental threats.", "control_type": "Physical", "frequency": "Continuous monitoring; semi-annual testing", "fedramp_delta": False, "mappings": {"soc2": ["A1.2"], "iso27001": ["A.7.5", "A.7.8", "A.7.11", "A.7.12"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-03"], "nist_800_53": ["PE-10", "PE-11", "PE-11(1)", "PE-12", "PE-13", "PE-13(1)", "PE-13(2)", "PE-14", "PE-15"], "fedramp": ["PE-10", "PE-11", "PE-11(1)", "PE-12", "PE-13", "PE-13(1)", "PE-13(2)", "PE-14", "PE-15"], "pci_dss": ["9.1.1"], "hipaa": ["§164.310(a)(2)(ii)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-PHY-04", "title": "Equipment Security and Maintenance", "description": "The organization protects equipment from theft, loss, and unauthorized access. Equipment is maintained per manufacturer specifications.", "objective": "Ensure equipment remains secure and operational.", "control_type": "Physical", "frequency": "Continuous; scheduled maintenance", "fedramp_delta": False, "mappings": {"soc2": ["CC6.4", "CC6.5"], "iso27001": ["A.7.8", "A.7.9", "A.7.10", "A.7.13"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["MA-2", "MA-2(2)", "MA-3", "MA-3(1)", "MA-3(2)", "MA-4", "MA-4(3)", "MA-5", "MA-6", "PE-16"], "fedramp": ["MA-2", "MA-2(2)", "MA-3", "MA-3(1)", "MA-3(2)", "MA-4", "MA-4(3)", "MA-5", "MA-6"], "pci_dss": ["9.4.3"], "hipaa": ["§164.310(c)"], "gdpr": [], "ccpa": []}}
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
            {"id": "CCF-OPS-01", "title": "System Hardening", "description": "The organization establishes system hardening standards for all OS, databases, containers, and network devices. Systems are hardened prior to deployment and compliance is continuously monitored against approved baselines (e.g., CIS Benchmarks, STIGs).", "objective": "Reduce attack surface.", "control_type": "Technical", "frequency": "At provisioning; continuous drift detection", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC6.8", "CC7.1"], "iso27001": ["A.8.9"], "iso27017": ["12.1.1"], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["CM-6", "CM-6(1)", "CM-7", "CM-7(1)", "CM-7(2)", "SC-2"], "fedramp": ["CM-6", "CM-6(1)", "CM-7", "CM-7(1)", "CM-7(2)"], "pci_dss": ["2.2", "2.2.1", "2.2.4"], "hipaa": ["§164.312(a)(1)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-OPS-02", "title": "Vulnerability Management", "description": "The organization maintains a vulnerability management program including regular scanning (infrastructure, application, container), prioritization, and remediation within defined SLAs. For FedRAMP: monthly authenticated OS/infrastructure scanning, monthly web application scanning, annual penetration testing.", "objective": "Identify and remediate vulnerabilities before exploitation.", "control_type": "Operational", "frequency": "Monthly scanning (FedRAMP); remediation per SLA", "fedramp_delta": True, "mappings": {"soc2": ["CC7.1", "CC3.2"], "iso27001": ["A.8.8"], "iso27017": ["12.6.1"], "iso27018": [], "nist_csf": ["ID.RA-01", "PR.IR-01"], "nist_800_53": ["RA-5", "RA-5(2)", "RA-5(5)", "SI-2", "SI-2(2)"], "fedramp": ["RA-5", "RA-5(2)", "RA-5(5)", "SI-2", "SI-2(2)", "FedRAMP Vuln Scan Requirements"], "pci_dss": ["6.3.1", "11.3.1", "11.3.2"], "hipaa": ["§164.308(a)(1)(ii)(A)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-OPS-03", "title": "Patch Management", "description": "The organization implements patch management ensuring timely application of security patches. For FedRAMP High: critical patches within 30 days, high within 60 days, moderate within 90 days. Emergency patches follow expedited procedures.", "objective": "Remediate known vulnerabilities through timely patching.", "control_type": "Operational", "frequency": "Continuous; patching per SLA", "fedramp_delta": True, "mappings": {"soc2": ["CC7.1"], "iso27001": ["A.8.8", "A.8.19"], "iso27017": ["12.6.1"], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SI-2", "SI-2(2)", "SI-2(3)"], "fedramp": ["SI-2", "SI-2(2)", "SI-2(3)", "FedRAMP Patch Timelines"], "pci_dss": ["6.3.3"], "hipaa": ["§164.308(a)(1)(ii)(A)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-OPS-04", "title": "Malware Protection", "description": "The organization deploys endpoint protection (EPP/EDR) across all endpoints and servers with automatic updates, real-time monitoring, and centralized management.", "objective": "Detect and prevent malware infections.", "control_type": "Technical", "frequency": "Continuous; real-time", "fedramp_delta": False, "mappings": {"soc2": ["CC6.8", "CC7.1"], "iso27001": ["A.8.7"], "iso27017": ["12.2.1"], "iso27018": [], "nist_csf": ["DE.CM-01"], "nist_800_53": ["SI-3", "SI-3(1)", "SI-3(2)"], "fedramp": ["SI-3", "SI-3(1)", "SI-3(2)"], "pci_dss": ["5.2", "5.3"], "hipaa": ["§164.308(a)(5)(ii)(B)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-OPS-05", "title": "Backup Management", "description": "The organization performs regular backups of critical data and configurations. Backups are encrypted, tested for recoverability, and stored in geographically separated locations.", "objective": "Ensure data and system recoverability.", "control_type": "Operational", "frequency": "Daily backups (or per RPO); quarterly restore testing", "fedramp_delta": False, "mappings": {"soc2": ["A1.2", "CC7.5"], "iso27001": ["A.8.13"], "iso27017": ["12.3.1"], "iso27018": ["A.9.4.2"], "nist_csf": ["PR.DS-04"], "nist_800_53": ["CP-9", "CP-9(1)", "CP-9(3)", "CP-10"], "fedramp": ["CP-9", "CP-9(1)", "CP-9(3)", "CP-10"], "pci_dss": ["9.4.1.1"], "hipaa": ["§164.308(a)(7)(ii)(A)"], "gdpr": ["Art. 32(1)(c)"], "ccpa": []}},
            {"id": "CCF-OPS-06", "title": "Capacity and Performance Management", "description": "The organization monitors system capacity and performance to ensure adequate resources. Capacity thresholds trigger automated scaling or alerting.", "objective": "Ensure availability through proactive capacity management.", "control_type": "Operational", "frequency": "Continuous monitoring; quarterly capacity planning", "fedramp_delta": False, "mappings": {"soc2": ["A1.1", "A1.2"], "iso27001": ["A.8.6"], "iso27017": ["12.1.3"], "iso27018": [], "nist_csf": ["PR.IR-04"], "nist_800_53": ["CP-2", "SC-5"], "fedramp": ["CP-2", "SC-5"], "pci_dss": [], "hipaa": ["§164.308(a)(7)(ii)(B)"], "gdpr": ["Art. 32(1)(b)"], "ccpa": []}},
            {"id": "CCF-OPS-07", "title": "Clock Synchronization", "description": "The organization synchronizes system clocks to authoritative time sources (e.g., NTP from NIST or USNO). Time synchronization accuracy supports audit log correlation and forensic investigation.", "objective": "Ensure accurate timestamps across all systems.", "control_type": "Technical", "frequency": "Continuous; quarterly verification", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2"], "iso27001": ["A.8.17"], "iso27017": [], "iso27018": [], "nist_csf": ["DE.AE-05"], "nist_800_53": ["AU-8", "AU-8(1)"], "fedramp": ["AU-8", "AU-8(1)"], "pci_dss": ["10.6"], "hipaa": ["§164.312(b)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-OPS-08", "title": "Software Installation Restrictions", "description": "The organization enforces restrictions on software installation. Only authorized software may be installed on organizational systems. Unauthorized software is detected and removed. Application whitelisting is implemented on high-security systems.", "objective": "Prevent execution of unauthorized or malicious software.", "control_type": "Technical", "frequency": "Continuous enforcement; monthly software inventory review", "fedramp_delta": True, "mappings": {"soc2": ["CC6.8"], "iso27001": ["A.8.19"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["CM-11", "CM-7(4)", "CM-7(5)"], "fedramp": ["CM-11", "CM-7(4)", "CM-7(5)"], "pci_dss": [], "hipaa": [], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: NET - Network Security
    # =========================================================================
    {
        "id": "NET",
        "name": "Network Security",
        "description": "Controls protecting organizational networks.",
        "controls": [
            {"id": "CCF-NET-01", "title": "Network Architecture and Segmentation", "description": "The organization designs and maintains network architecture segmenting systems by trust level, data sensitivity, and function. Production, staging, development, and corporate environments are segmented.", "objective": "Limit blast radius and enforce data isolation.", "control_type": "Technical", "frequency": "Continuous; annual architecture review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC6.6"], "iso27001": ["A.8.22"], "iso27017": ["13.1.3"], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SC-7", "SC-7(5)", "SC-7(18)", "AC-4"], "fedramp": ["SC-7", "SC-7(5)", "SC-7(18)", "AC-4"], "pci_dss": ["1.2.1", "1.3.1", "1.3.2"], "hipaa": ["§164.312(e)(1)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-NET-02", "title": "Firewall and Security Group Management", "description": "The organization implements firewalls, security groups, and network ACLs with deny-by-default rules. Rules are documented with business justification and reviewed semi-annually.", "objective": "Control network traffic flow.", "control_type": "Technical", "frequency": "Continuous; semi-annual rule review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC6.6"], "iso27001": ["A.8.20", "A.8.21"], "iso27017": ["13.1.1"], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SC-7(5)", "SC-7(8)"], "fedramp": ["SC-7(5)", "SC-7(8)"], "pci_dss": ["1.2.1", "1.2.5", "1.2.6"], "hipaa": ["§164.312(e)(1)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-NET-03", "title": "Intrusion Detection and Prevention", "description": "The organization deploys IDS/IPS at critical boundaries. Detection signatures are updated regularly. Alerts are monitored, triaged, and investigated.", "objective": "Detect and block malicious network activity.", "control_type": "Technical", "frequency": "Continuous; daily signature updates", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2", "CC7.3"], "iso27001": ["A.8.16"], "iso27017": [], "iso27018": [], "nist_csf": ["DE.CM-01"], "nist_800_53": ["SI-4", "SI-4(2)", "SI-4(4)", "SI-4(5)"], "fedramp": ["SI-4", "SI-4(2)", "SI-4(4)", "SI-4(5)"], "pci_dss": ["11.5", "11.5.1"], "hipaa": ["§164.312(b)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-NET-04", "title": "Web Application Firewall", "description": "The organization deploys WAF in front of all public-facing web applications. WAF is tuned for OWASP Top 10 protection.", "objective": "Protect web applications from common attacks.", "control_type": "Technical", "frequency": "Continuous; quarterly rule review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.6"], "iso27001": ["A.8.20"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01", "DE.CM-06"], "nist_800_53": ["SC-7", "SI-4"], "fedramp": ["SC-7", "SI-4"], "pci_dss": ["6.4.1", "6.4.2"], "hipaa": [], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-NET-05", "title": "DDoS Protection", "description": "The organization implements DDoS protection for public-facing services including volumetric, protocol, and application-layer mitigation.", "objective": "Maintain availability against DoS attacks.", "control_type": "Technical", "frequency": "Continuous; annual DDoS simulation", "fedramp_delta": False, "mappings": {"soc2": ["A1.2", "CC6.6"], "iso27001": ["A.8.20"], "iso27017": ["13.1.3"], "iso27018": [], "nist_csf": ["PR.IR-04"], "nist_800_53": ["SC-5", "SC-5(2)"], "fedramp": ["SC-5", "SC-5(2)"], "pci_dss": ["11.5"], "hipaa": ["§164.308(a)(7)(i)"], "gdpr": ["Art. 32(1)(b)"], "ccpa": []}},
            {"id": "CCF-NET-06", "title": "DNS Security", "description": "The organization implements DNS security including DNSSEC, DNS filtering, and monitoring for DNS-based attacks.", "objective": "Protect DNS infrastructure.", "control_type": "Technical", "frequency": "Continuous; annual review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.6"], "iso27001": ["A.8.20"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SC-20", "SC-21", "SC-22"], "fedramp": ["SC-20", "SC-21", "SC-22"], "pci_dss": [], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-NET-07", "title": "Boundary Protection and Authorization Boundary", "description": "The organization defines and documents the authorization boundary of the information system. Boundary protections monitor and control communications at managed interfaces, particularly at external boundaries and key internal boundaries. Connections to external systems require explicit authorization and documentation of security requirements.", "objective": "Define, protect, and monitor the system boundary to prevent unauthorized data flows.", "control_type": "Technical", "frequency": "Continuous enforcement; annual boundary review; documented in SSP", "fedramp_delta": True, "mappings": {"soc2": ["CC6.6"], "iso27001": ["A.8.20", "A.8.22"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SC-7", "SC-7(3)", "SC-7(4)", "SC-7(7)", "SC-7(8)", "CA-3", "CA-3(6)"], "fedramp": ["SC-7", "SC-7(3)", "SC-7(4)", "SC-7(7)", "SC-7(8)", "CA-3", "CA-3(6)", "FedRAMP Auth Boundary"], "pci_dss": ["1.2.1"], "hipaa": ["§164.312(e)(1)"], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: SDL - Secure Development Lifecycle
    # =========================================================================
    {
        "id": "SDL",
        "name": "Secure Development Lifecycle",
        "description": "Controls ensuring security is integrated throughout the SDLC.",
        "controls": [
            {"id": "CCF-SDL-01", "title": "Secure Development Policy", "description": "The organization establishes a secure development policy mandating security activities throughout the SDLC.", "objective": "Ensure security is a first-class requirement.", "control_type": "Administrative", "frequency": "Annual review", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.25", "A.8.26"], "iso27017": ["14.1.1"], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SA-3", "SA-15"], "fedramp": ["SA-3", "SA-15"], "pci_dss": ["6.2", "6.2.1"], "hipaa": ["§164.312(a)(1)"], "gdpr": ["Art. 25"], "ccpa": []}},
            {"id": "CCF-SDL-02", "title": "Security Requirements in Design", "description": "The organization incorporates security and privacy requirements into the design phase. Threat modeling or security design reviews are conducted for new features and significant changes.", "objective": "Identify security risks early in design.", "control_type": "Operational", "frequency": "Per feature/project", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.25"], "iso27017": ["14.1.1"], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SA-8", "SA-11"], "fedramp": ["SA-8", "SA-11"], "pci_dss": ["6.2.1"], "hipaa": [], "gdpr": ["Art. 25(1)"], "ccpa": []}},
            {"id": "CCF-SDL-03", "title": "Code Review", "description": "The organization requires peer code review for all production code changes prior to merge and deployment.", "objective": "Catch defects and security issues before production.", "control_type": "Operational", "frequency": "Per code change", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.25"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["SA-11"], "fedramp": ["SA-11"], "pci_dss": ["6.2.3.1"], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-SDL-04", "title": "Static and Dynamic Application Security Testing", "description": "The organization integrates SAST and DAST into the CI/CD pipeline. Findings are triaged and remediated per SLAs.", "objective": "Identify application vulnerabilities through automated testing.", "control_type": "Technical", "frequency": "SAST every build; DAST per release or monthly", "fedramp_delta": False, "mappings": {"soc2": ["CC7.1", "CC8.1"], "iso27001": ["A.8.25", "A.8.29"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01", "DE.CM-06"], "nist_800_53": ["SA-11", "SA-11(1)"], "fedramp": ["SA-11", "SA-11(1)"], "pci_dss": ["6.2.4", "11.3.1"], "hipaa": ["§164.308(a)(1)(ii)(A)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-SDL-05", "title": "Penetration Testing", "description": "The organization conducts penetration testing at least annually. For FedRAMP: annual third-party penetration testing covering the full authorization boundary per FedRAMP penetration test guidance.", "objective": "Validate controls through adversarial testing.", "control_type": "Operational", "frequency": "Annual (minimum); per FedRAMP pen test guidance", "fedramp_delta": True, "mappings": {"soc2": ["CC4.1", "CC7.1"], "iso27001": ["A.8.8"], "iso27017": [], "iso27018": [], "nist_csf": ["ID.RA-01"], "nist_800_53": ["CA-8", "CA-8(1)"], "fedramp": ["CA-8", "CA-8(1)", "FedRAMP Pen Test Guidance"], "pci_dss": ["11.4", "11.4.1"], "hipaa": ["§164.308(a)(8)"], "gdpr": ["Art. 32(1)(d)"], "ccpa": []}},
            {"id": "CCF-SDL-06", "title": "Software Dependency and Supply Chain Security", "description": "The organization maintains controls over third-party dependencies including SCA, SBOM generation, and license compliance. Vulnerable dependencies are remediated per SLAs.", "objective": "Manage risks from third-party components.", "control_type": "Technical", "frequency": "Continuous; quarterly dependency review", "fedramp_delta": False, "mappings": {"soc2": ["CC7.1", "CC9.2"], "iso27001": ["A.8.28"], "iso27017": [], "iso27018": [], "nist_csf": ["ID.RA-01"], "nist_800_53": ["SA-12", "SR-3", "SR-4"], "fedramp": ["SA-12", "SR-3", "SR-4"], "pci_dss": ["6.3.2"], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-SDL-07", "title": "Environment Separation", "description": "The organization maintains separate development, testing, and production environments. Production data is not used in non-production without anonymization.", "objective": "Prevent unauthorized changes and data exposure through environment isolation.", "control_type": "Technical", "frequency": "Continuous enforcement", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC8.1"], "iso27001": ["A.8.25", "A.8.31"], "iso27017": ["12.1.4"], "iso27018": ["A.11.6"], "nist_csf": ["PR.DS-01"], "nist_800_53": ["CM-4", "SA-11"], "fedramp": ["CM-4", "SA-11"], "pci_dss": ["6.5.1", "6.5.2", "6.5.3"], "hipaa": ["§164.312(a)(1)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-SDL-08", "title": "Developer Security Training", "description": "The organization provides annual security training to developers covering secure coding practices, OWASP Top 10, language-specific vulnerabilities, and the organization's secure development standards. Training completion is tracked.", "objective": "Ensure developers have current knowledge of secure coding practices.", "control_type": "Administrative", "frequency": "Annual; upon onboarding of new developers", "fedramp_delta": True, "mappings": {"soc2": ["CC1.4"], "iso27001": ["A.6.3"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.AT-02"], "nist_800_53": ["AT-3", "SA-16"], "fedramp": ["AT-3", "SA-16"], "pci_dss": ["6.2.2"], "hipaa": [], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: CHM - Change Management (same structure, enhanced 800-53)
    # =========================================================================
    {
        "id": "CHM",
        "name": "Change Management",
        "description": "Controls governing changes to information systems, infrastructure, and applications.",
        "controls": [
            {"id": "CCF-CHM-01", "title": "Change Management Policy and Process", "description": "The organization establishes change management covering standard, normal, and emergency changes with appropriate governance.", "objective": "Ensure changes are controlled, authorized, and traceable.", "control_type": "Administrative", "frequency": "Annual policy review; per-change execution", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.32"], "iso27017": ["12.1.2"], "iso27018": [], "nist_csf": ["PR.IP-03"], "nist_800_53": ["CM-1", "CM-3", "CM-3(2)"], "fedramp": ["CM-1", "CM-3", "CM-3(2)"], "pci_dss": ["6.5.1"], "hipaa": ["§164.312(a)(1)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-CHM-02", "title": "Change Authorization and Approval", "description": "All production changes require documented approval. Developers cannot self-approve (segregation of duties).", "objective": "Prevent unauthorized production changes.", "control_type": "Operational", "frequency": "Per change", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.32"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IP-03"], "nist_800_53": ["CM-3(1)", "CM-5"], "fedramp": ["CM-3(1)", "CM-5"], "pci_dss": ["6.5.1", "6.5.2"], "hipaa": ["§164.312(a)(1)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-CHM-03", "title": "Change Testing and Validation", "description": "Changes are tested in non-production prior to deployment including functional, regression, and security testing.", "objective": "Prevent defects in production.", "control_type": "Operational", "frequency": "Per change", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.29", "A.8.32"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IP-03"], "nist_800_53": ["CM-4", "CM-4(1)", "SA-11"], "fedramp": ["CM-4", "CM-4(1)", "SA-11"], "pci_dss": ["6.2.3", "6.5.3"], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-CHM-04", "title": "Emergency Change Process", "description": "Emergency changes require post-implementation review, retroactive approval, and documentation within defined timeframes.", "objective": "Enable rapid response while maintaining accountability.", "control_type": "Operational", "frequency": "Per occurrence; retroactive review within 48 hours", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.32"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IP-03"], "nist_800_53": ["CM-3(1)"], "fedramp": ["CM-3(1)"], "pci_dss": ["6.5.1"], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-CHM-05", "title": "Configuration Management", "description": "The organization maintains and enforces approved configuration baselines. Configuration is managed as code where possible. Deviations are detected and remediated.", "objective": "Maintain known-good configurations and detect drift.", "control_type": "Technical", "frequency": "Continuous; quarterly baseline review", "fedramp_delta": False, "mappings": {"soc2": ["CC7.1", "CC8.1"], "iso27001": ["A.8.9"], "iso27017": ["12.1.1"], "iso27018": [], "nist_csf": ["PR.IP-01"], "nist_800_53": ["CM-2", "CM-2(1)", "CM-2(3)", "CM-2(7)", "CM-3", "CM-6"], "fedramp": ["CM-2", "CM-2(1)", "CM-2(3)", "CM-2(7)", "CM-3", "CM-6"], "pci_dss": ["2.2"], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-CHM-06", "title": "Release Management", "description": "The organization governs release packaging, scheduling, and deployment including rollback plans and post-deployment monitoring.", "objective": "Ensure reliable and controlled deployment.", "control_type": "Operational", "frequency": "Per release", "fedramp_delta": False, "mappings": {"soc2": ["CC8.1"], "iso27001": ["A.8.32"], "iso27017": ["14.2.2"], "iso27018": [], "nist_csf": ["PR.IP-03"], "nist_800_53": ["CM-3", "SA-10"], "fedramp": ["CM-3", "SA-10"], "pci_dss": ["6.5.1", "6.5.4"], "hipaa": [], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: LOG - Logging and Monitoring
    # =========================================================================
    {
        "id": "LOG",
        "name": "Logging and Monitoring",
        "description": "Controls for comprehensive logging, centralized monitoring, and detection.",
        "controls": [
            {"id": "CCF-LOG-01", "title": "Audit Logging Standards", "description": "The organization defines and enforces audit logging standards specifying events, data fields (who, what, when, where, outcome), and scope. For FedRAMP High, all AU-2 events are logged and audit records include AU-3 content requirements.", "objective": "Capture security-relevant events consistently.", "control_type": "Technical", "frequency": "Continuous; annual logging review", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2"], "iso27001": ["A.8.15"], "iso27017": ["12.4.1"], "iso27018": ["A.12.4.1"], "nist_csf": ["DE.AE-03"], "nist_800_53": ["AU-1", "AU-2", "AU-3", "AU-3(1)"], "fedramp": ["AU-1", "AU-2", "AU-3", "AU-3(1)"], "pci_dss": ["10.2", "10.2.1"], "hipaa": ["§164.312(b)"], "gdpr": ["Art. 30"], "ccpa": []}},
            {"id": "CCF-LOG-02", "title": "Centralized Log Collection and Aggregation", "description": "Logs from all in-scope systems are collected into a centralized SIEM. For FedRAMP, log collection covers the entire authorization boundary.", "objective": "Enable correlated analysis and investigation.", "control_type": "Technical", "frequency": "Continuous; monthly coverage review", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2", "CC7.3"], "iso27001": ["A.8.15"], "iso27017": ["12.4.1"], "iso27018": [], "nist_csf": ["DE.AE-03"], "nist_800_53": ["AU-6", "AU-6(1)", "AU-6(3)", "SI-4"], "fedramp": ["AU-6", "AU-6(1)", "AU-6(3)"], "pci_dss": ["10.3", "10.3.3"], "hipaa": ["§164.312(b)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-LOG-03", "title": "Log Retention", "description": "Audit logs are retained for a minimum of one year with 90 days online. For FedRAMP High, logs must be available for immediate retrieval for 90 days and retained for at least one year.", "objective": "Ensure logs are available for investigation and audit.", "control_type": "Technical", "frequency": "Continuous; annual retention review", "fedramp_delta": True, "mappings": {"soc2": ["CC7.2"], "iso27001": ["A.8.15"], "iso27017": ["12.4.1"], "iso27018": ["A.12.4.1"], "nist_csf": ["DE.AE-03"], "nist_800_53": ["AU-11"], "fedramp": ["AU-11", "FedRAMP: 1yr retention, 90d online"], "pci_dss": ["10.5.1"], "hipaa": ["§164.312(b)"], "gdpr": ["Art. 5(1)(e)"], "ccpa": []}},
            {"id": "CCF-LOG-04", "title": "Security Monitoring and Alerting", "description": "The organization implements 24/7 security monitoring with detection rules, alerting, and investigation SLAs. Monitoring covers IoCs, anomalous behavior, and high-risk events.", "objective": "Detect incidents timely through active monitoring.", "control_type": "Technical", "frequency": "Continuous (24/7); monthly rule review", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2", "CC7.3"], "iso27001": ["A.8.16"], "iso27017": ["12.4.1"], "iso27018": [], "nist_csf": ["DE.CM-01", "DE.CM-06", "DE.AE-02"], "nist_800_53": ["SI-4", "SI-4(2)", "IR-4"], "fedramp": ["SI-4", "SI-4(2)"], "pci_dss": ["10.4.1", "10.7"], "hipaa": ["§164.308(a)(1)(ii)(D)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-LOG-05", "title": "Log Integrity Protection", "description": "Logs are protected from unauthorized modification or deletion using write-once storage, separate accounts, and access restrictions.", "objective": "Ensure trustworthy log data.", "control_type": "Technical", "frequency": "Continuous; annual review", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2"], "iso27001": ["A.8.15"], "iso27017": ["12.4.2"], "iso27018": [], "nist_csf": ["DE.AE-03"], "nist_800_53": ["AU-9", "AU-9(2)", "AU-9(4)", "AU-10"], "fedramp": ["AU-9", "AU-9(2)", "AU-9(4)", "AU-10"], "pci_dss": ["10.3.2"], "hipaa": ["§164.312(b)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-LOG-06", "title": "Audit Record Generation and Content", "description": "The information system generates audit records containing sufficient information to establish what type of event occurred, when it occurred, where it occurred, the source of the event, the outcome, and the identity of individuals or subjects associated with the event. Audit generation is configurable per FedRAMP AU-2 event list.", "objective": "Ensure audit records contain sufficient detail for investigation and accountability.", "control_type": "Technical", "frequency": "Continuous; audit event list reviewed annually", "fedramp_delta": True, "mappings": {"soc2": ["CC7.2"], "iso27001": ["A.8.15"], "iso27017": [], "iso27018": [], "nist_csf": ["DE.AE-03"], "nist_800_53": ["AU-2", "AU-3", "AU-12", "AU-12(1)", "AU-12(3)"], "fedramp": ["AU-2", "AU-3", "AU-12", "AU-12(1)", "AU-12(3)"], "pci_dss": ["10.2"], "hipaa": ["§164.312(b)"], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: INC - Incident Management
    # =========================================================================
    {
        "id": "INC",
        "name": "Incident Management",
        "description": "Controls for detection, response, and management of security incidents.",
        "controls": [
            {"id": "CCF-INC-01", "title": "Incident Response Plan", "description": "The organization maintains a documented IR plan covering classification, roles, communication, escalation, containment, and post-incident review. Tested at least annually.", "objective": "Structured and effective incident response.", "control_type": "Administrative", "frequency": "Annual review and testing", "fedramp_delta": False, "mappings": {"soc2": ["CC7.3", "CC7.4", "CC7.5"], "iso27001": ["A.5.24", "A.5.25", "A.5.26"], "iso27017": ["16.1.1"], "iso27018": ["A.16.1.1"], "nist_csf": ["RS.MA-01", "RS.MA-02"], "nist_800_53": ["IR-1", "IR-8", "IR-8(1)"], "fedramp": ["IR-1", "IR-8", "IR-8(1)"], "pci_dss": ["12.10.1", "12.10.2"], "hipaa": ["§164.308(a)(6)(i)"], "gdpr": ["Art. 33", "Art. 34"], "ccpa": []}},
            {"id": "CCF-INC-02", "title": "Incident Detection and Reporting", "description": "The organization implements automated and manual mechanisms for detecting and reporting incidents. All personnel are trained to report.", "objective": "Timely identification and reporting of incidents.", "control_type": "Operational", "frequency": "Continuous; training annually", "fedramp_delta": False, "mappings": {"soc2": ["CC7.2", "CC7.3"], "iso27001": ["A.6.8", "A.8.16"], "iso27017": ["16.1.2"], "iso27018": [], "nist_csf": ["DE.AE-02", "DE.AE-06"], "nist_800_53": ["IR-4", "IR-6", "IR-6(1)"], "fedramp": ["IR-4", "IR-6", "IR-6(1)"], "pci_dss": ["12.10.5"], "hipaa": ["§164.308(a)(6)(ii)"], "gdpr": ["Art. 33(1)"], "ccpa": []}},
            {"id": "CCF-INC-03", "title": "Incident Containment, Eradication, and Recovery", "description": "Procedures for containment, root cause eradication, and system recovery including restoration and integrity verification.", "objective": "Minimize impact and restore operations.", "control_type": "Operational", "frequency": "Per incident", "fedramp_delta": False, "mappings": {"soc2": ["CC7.4", "CC7.5"], "iso27001": ["A.5.26"], "iso27017": ["16.1.5"], "iso27018": [], "nist_csf": ["RS.MI-01", "RS.MI-02", "RC.RP-01"], "nist_800_53": ["IR-4", "IR-4(1)", "IR-5"], "fedramp": ["IR-4", "IR-4(1)", "IR-5"], "pci_dss": ["12.10.1"], "hipaa": ["§164.308(a)(7)(i)"], "gdpr": ["Art. 33"], "ccpa": []}},
            {"id": "CCF-INC-04", "title": "Incident Communication and Notification", "description": "The organization maintains communication procedures including internal escalation, customer notification, and regulatory reporting. For FedRAMP, incidents are reported to US-CERT/CISA within 1 hour of determination for certain categories per FedRAMP Incident Communications Procedure.", "objective": "Timely and appropriate communication during incidents.", "control_type": "Administrative", "frequency": "Per incident; FedRAMP: 1-hour reporting for certain categories", "fedramp_delta": True, "mappings": {"soc2": ["CC2.3", "CC7.3", "CC7.4"], "iso27001": ["A.5.24", "A.5.25"], "iso27017": ["16.1.2"], "iso27018": ["A.9.1"], "nist_csf": ["RS.CO-02", "RS.CO-03"], "nist_800_53": ["IR-6", "IR-6(1)", "IR-7", "IR-7(1)"], "fedramp": ["IR-6", "IR-6(1)", "IR-7", "IR-7(1)", "FedRAMP ICP: US-CERT 1hr reporting"], "pci_dss": ["12.10.1"], "hipaa": ["§164.308(a)(6)(ii)", "§164.404"], "gdpr": ["Art. 33", "Art. 34"], "ccpa": ["§1798.150(a)"]}},
            {"id": "CCF-INC-05", "title": "Post-Incident Review and Lessons Learned", "description": "Blameless postmortems for all significant incidents. Root cause analysis, lessons learned, and action items tracked.", "objective": "Continuous improvement of incident response.", "control_type": "Operational", "frequency": "After each significant incident; within 5 business days", "fedramp_delta": False, "mappings": {"soc2": ["CC4.2", "CC7.5"], "iso27001": ["A.5.27"], "iso27017": ["16.1.6"], "iso27018": [], "nist_csf": ["RS.IM-01", "RS.IM-02"], "nist_800_53": ["IR-4(4)"], "fedramp": ["IR-4(4)"], "pci_dss": ["12.10.2"], "hipaa": ["§164.308(a)(6)(ii)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-INC-06", "title": "Incident Response Training", "description": "The organization provides incident response training to IR team members within role assignment and at least annually thereafter. Training includes tabletop exercises, tool usage, forensic procedures, and communication protocols.", "objective": "Ensure IR team readiness through regular training and exercises.", "control_type": "Administrative", "frequency": "Annual; upon role assignment; after major exercises", "fedramp_delta": True, "mappings": {"soc2": ["CC7.3"], "iso27001": ["A.5.24"], "iso27017": [], "iso27018": [], "nist_csf": ["RS.MA-01"], "nist_800_53": ["IR-2", "IR-2(1)", "IR-2(2)"], "fedramp": ["IR-2", "IR-2(1)", "IR-2(2)"], "pci_dss": ["12.10.1"], "hipaa": [], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: BCP - Business Continuity and DR
    # =========================================================================
    {
        "id": "BCP",
        "name": "Business Continuity and Disaster Recovery",
        "description": "Controls ensuring operational resilience and recovery from disruptions.",
        "controls": [
            {"id": "CCF-BCP-01", "title": "Business Continuity Plan", "description": "The organization maintains a BCP identifying critical functions, dependencies, and recovery priorities. Tested annually.", "objective": "Continue essential operations during disruptions.", "control_type": "Administrative", "frequency": "Annual review and testing", "fedramp_delta": False, "mappings": {"soc2": ["A1.2", "A1.3"], "iso27001": ["A.5.29", "A.5.30"], "iso27017": [], "iso27018": [], "nist_csf": ["RC.RP-01", "RC.RP-02"], "nist_800_53": ["CP-1", "CP-2", "CP-2(1)", "CP-2(3)", "CP-2(8)"], "fedramp": ["CP-1", "CP-2", "CP-2(1)", "CP-2(3)", "CP-2(8)"], "pci_dss": [], "hipaa": ["§164.308(a)(7)(i)"], "gdpr": ["Art. 32(1)(c)"], "ccpa": []}},
            {"id": "CCF-BCP-02", "title": "Disaster Recovery Plan", "description": "The organization maintains a DRP defining procedures for restoring IT systems and data. RTO and RPO are specified and validated.", "objective": "Timely recovery of technology systems.", "control_type": "Administrative", "frequency": "Annual review; testing per CCF-BCP-03", "fedramp_delta": False, "mappings": {"soc2": ["A1.2", "CC7.5"], "iso27001": ["A.5.30", "A.8.14"], "iso27017": ["17.1.1"], "iso27018": [], "nist_csf": ["RC.RP-01"], "nist_800_53": ["CP-2", "CP-10", "CP-10(2)"], "fedramp": ["CP-2", "CP-10", "CP-10(2)"], "pci_dss": [], "hipaa": ["§164.308(a)(7)(ii)(B)"], "gdpr": ["Art. 32(1)(c)"], "ccpa": []}},
            {"id": "CCF-BCP-03", "title": "BCP/DR Testing and Exercising", "description": "Tests BCP/DR plans annually through tabletop, functional, or full-scale exercises. Validates recovery procedures and RTO/RPO.", "objective": "Validate plan effectiveness and personnel preparedness.", "control_type": "Operational", "frequency": "Annual; semi-annual for critical systems", "fedramp_delta": False, "mappings": {"soc2": ["A1.3"], "iso27001": ["A.5.30"], "iso27017": ["17.1.2"], "iso27018": [], "nist_csf": ["RC.RP-03"], "nist_800_53": ["CP-4", "CP-4(1)"], "fedramp": ["CP-4", "CP-4(1)"], "pci_dss": [], "hipaa": ["§164.308(a)(7)(ii)(D)"], "gdpr": ["Art. 32(1)(d)"], "ccpa": []}},
            {"id": "CCF-BCP-04", "title": "High Availability and Redundancy", "description": "Critical systems designed with multi-AZ/multi-region redundancy, failover, and elimination of single points of failure.", "objective": "Minimize disruptions through resilient architecture.", "control_type": "Technical", "frequency": "Continuous; annual review; semi-annual failover testing", "fedramp_delta": False, "mappings": {"soc2": ["A1.1", "A1.2"], "iso27001": ["A.8.14"], "iso27017": ["17.2.1"], "iso27018": [], "nist_csf": ["PR.IR-04", "RC.RP-01"], "nist_800_53": ["CP-7", "CP-7(1)", "CP-7(2)", "CP-7(3)", "CP-8", "CP-8(1)", "CP-8(2)"], "fedramp": ["CP-7", "CP-7(1)", "CP-7(2)", "CP-7(3)", "CP-8", "CP-8(1)", "CP-8(2)"], "pci_dss": [], "hipaa": ["§164.308(a)(7)(ii)(C)"], "gdpr": ["Art. 32(1)(b)"], "ccpa": []}},
            {"id": "CCF-BCP-05", "title": "Alternate Processing and Storage Sites", "description": "The organization establishes alternate processing and storage sites that are geographically separated from the primary site. Alternate sites are equipped and configured to support recovery operations within defined RTO/RPO. Transfer agreements and network connectivity to alternate sites are established and tested.", "objective": "Ensure recovery capability through geographically distributed infrastructure.", "control_type": "Technical", "frequency": "Continuous availability; annual failover testing to alternate site", "fedramp_delta": True, "mappings": {"soc2": ["A1.2"], "iso27001": ["A.8.14"], "iso27017": [], "iso27018": [], "nist_csf": ["RC.RP-01"], "nist_800_53": ["CP-6", "CP-6(1)", "CP-6(2)", "CP-6(3)", "CP-7", "CP-7(1)"], "fedramp": ["CP-6", "CP-6(1)", "CP-6(2)", "CP-6(3)", "CP-7", "CP-7(1)"], "pci_dss": [], "hipaa": [], "gdpr": [], "ccpa": []}},
            {"id": "CCF-BCP-06", "title": "Contingency Plan Training", "description": "The organization provides contingency plan training to designated personnel within 10 days of role assignment and annually thereafter. Training covers roles, responsibilities, plan procedures, and coordination requirements.", "objective": "Ensure personnel are prepared to execute contingency plans.", "control_type": "Administrative", "frequency": "Within 10 days of role assignment; annual refresher", "fedramp_delta": True, "mappings": {"soc2": [], "iso27001": ["A.5.30"], "iso27017": [], "iso27018": [], "nist_csf": ["RC.RP-03"], "nist_800_53": ["CP-3", "CP-3(1)"], "fedramp": ["CP-3", "CP-3(1)"], "pci_dss": [], "hipaa": [], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: VND - Vendor Management
    # =========================================================================
    {
        "id": "VND",
        "name": "Vendor and Third-Party Management",
        "description": "Controls governing assessment, selection, and monitoring of third-party providers.",
        "controls": [
            {"id": "CCF-VND-01", "title": "Vendor Risk Assessment", "description": "The organization conducts risk assessments of vendors prior to engagement and periodically. Assessment rigor is proportionate to criticality and data access.", "objective": "Evaluate and manage third-party security risks.", "control_type": "Administrative", "frequency": "Pre-engagement; annual for critical vendors", "fedramp_delta": False, "mappings": {"soc2": ["CC9.2"], "iso27001": ["A.5.19", "A.5.20", "A.5.21"], "iso27017": ["CLD.6.3"], "iso27018": ["A.15.1.1"], "nist_csf": ["GV.SC-03", "GV.SC-06"], "nist_800_53": ["SA-9", "SA-9(2)", "SR-2", "SR-5", "SR-6"], "fedramp": ["SA-9", "SA-9(2)", "SR-2", "SR-5", "SR-6"], "pci_dss": ["12.8", "12.8.1"], "hipaa": ["§164.308(b)(1)"], "gdpr": ["Art. 28(1)"], "ccpa": ["§1798.140(w)"]}},
            {"id": "CCF-VND-02", "title": "Vendor Security Requirements and Contracts", "description": "Vendor contracts include security and privacy requirements, incident notification, audit rights, and data return/destruction provisions.", "objective": "Establish binding vendor security obligations.", "control_type": "Administrative", "frequency": "At contract execution; renewal", "fedramp_delta": False, "mappings": {"soc2": ["CC9.2"], "iso27001": ["A.5.19", "A.5.20"], "iso27017": ["CLD.6.3"], "iso27018": ["A.15.1.2"], "nist_csf": ["GV.SC-05"], "nist_800_53": ["SA-4", "SA-9"], "fedramp": ["SA-4", "SA-9"], "pci_dss": ["12.8.2", "12.8.5"], "hipaa": ["§164.308(b)(1)", "§164.314(a)(2)"], "gdpr": ["Art. 28(3)"], "ccpa": ["§1798.140(w)"]}},
            {"id": "CCF-VND-03", "title": "Vendor Monitoring and Oversight", "description": "Ongoing monitoring of vendor compliance including certification review, incident tracking, and periodic reassessment.", "objective": "Ensure vendors maintain security standards.", "control_type": "Operational", "frequency": "Annual; quarterly for tier-1", "fedramp_delta": False, "mappings": {"soc2": ["CC9.2", "CC4.1"], "iso27001": ["A.5.22"], "iso27017": ["15.2.1"], "iso27018": [], "nist_csf": ["GV.SC-09", "GV.SC-10"], "nist_800_53": ["SA-9(2)", "CA-7"], "fedramp": ["SA-9(2)", "CA-7"], "pci_dss": ["12.8.4"], "hipaa": ["§164.308(b)(1)"], "gdpr": ["Art. 28(3)(h)"], "ccpa": []}},
            {"id": "CCF-VND-04", "title": "Subprocessor Management", "description": "Visibility into vendor subprocessors. Vendors notify of new subprocessors and ensure equivalent security. Subprocessor list maintained.", "objective": "Extend oversight to downstream providers.", "control_type": "Administrative", "frequency": "Continuous notification; annual review", "fedramp_delta": False, "mappings": {"soc2": ["CC9.2"], "iso27001": ["A.5.19", "A.5.21"], "iso27017": ["CLD.6.3"], "iso27018": ["A.15.1.3"], "nist_csf": ["GV.SC-07"], "nist_800_53": ["SA-9", "SR-6"], "fedramp": ["SA-9", "SR-6"], "pci_dss": ["12.8.5"], "hipaa": ["§164.314(a)(2)(i)"], "gdpr": ["Art. 28(2)", "Art. 28(4)"], "ccpa": ["§1798.140(w)"]}},
            {"id": "CCF-VND-05", "title": "Supply Chain Risk Management", "description": "The organization develops and implements a supply chain risk management plan that identifies, assesses, and mitigates risks throughout the supply chain. The plan addresses acquisition processes, supplier diversity, counterfeit component detection, and supply chain threat analysis. For FedRAMP, supply chain controls align with NIST 800-161.", "objective": "Manage end-to-end supply chain security risks.", "control_type": "Administrative", "frequency": "Annual plan review; continuous risk monitoring", "fedramp_delta": True, "mappings": {"soc2": ["CC9.2"], "iso27001": ["A.5.21"], "iso27017": [], "iso27018": [], "nist_csf": ["GV.SC-01", "GV.SC-02", "GV.SC-04"], "nist_800_53": ["SR-1", "SR-2", "SR-3", "SR-5", "SR-6", "SR-11"], "fedramp": ["SR-1", "SR-2", "SR-3", "SR-5", "SR-6", "SR-11", "NIST SP 800-161"], "pci_dss": [], "hipaa": [], "gdpr": [], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: PRI - Privacy (same as commercial, privacy frameworks don't change for FedRAMP)
    # =========================================================================
    {
        "id": "PRI",
        "name": "Privacy",
        "description": "Controls governing collection, processing, storage, and protection of personal data.",
        "controls": [
            {"id": "CCF-PRI-01", "title": "Privacy Policy and Notice", "description": "Public-facing privacy notice covering data categories, purposes, sharing, rights, and contact info. Reviewed annually.", "objective": "Transparent disclosure of data practices.", "control_type": "Administrative", "frequency": "Annual review", "fedramp_delta": False, "mappings": {"soc2": ["P1.1", "P1.2"], "iso27001": [], "iso27017": [], "iso27018": ["A.2.1"], "nist_csf": ["GV.PO-01"], "nist_800_53": ["PT-3", "PT-5"], "fedramp": ["PT-3", "PT-5"], "pci_dss": [], "hipaa": ["§164.520"], "gdpr": ["Art. 12", "Art. 13", "Art. 14"], "ccpa": ["§1798.100(a)", "§1798.130"]}},
            {"id": "CCF-PRI-02", "title": "Data Processing Inventory (RoPA)", "description": "Record of processing activities maintained and available for regulatory review.", "objective": "Comprehensive processing activity inventory.", "control_type": "Administrative", "frequency": "Continuous; quarterly review", "fedramp_delta": False, "mappings": {"soc2": ["P1.1"], "iso27001": ["A.5.9"], "iso27017": [], "iso27018": ["A.2.5"], "nist_csf": ["ID.AM-05"], "nist_800_53": ["PT-3", "PM-25"], "fedramp": ["PT-3", "PM-25"], "pci_dss": [], "hipaa": [], "gdpr": ["Art. 30"], "ccpa": ["§1798.100(a)"]}},
            {"id": "CCF-PRI-03", "title": "Consent Management", "description": "Consent obtained and managed where applicable. Mechanisms for recording and honoring withdrawal.", "objective": "Lawful consent-based processing.", "control_type": "Operational", "frequency": "Per data collection event", "fedramp_delta": False, "mappings": {"soc2": ["P2.1"], "iso27001": [], "iso27017": [], "iso27018": ["A.2.1"], "nist_csf": [], "nist_800_53": ["PT-4"], "fedramp": ["PT-4"], "pci_dss": [], "hipaa": ["§164.508"], "gdpr": ["Art. 6(1)(a)", "Art. 7"], "ccpa": ["§1798.120", "§1798.135"]}},
            {"id": "CCF-PRI-04", "title": "Data Subject Rights Management", "description": "Processes for receiving and responding to data subject rights requests within legal timeframes.", "objective": "Enable individuals to exercise privacy rights.", "control_type": "Operational", "frequency": "Per request; within required timeframes", "fedramp_delta": False, "mappings": {"soc2": ["P4.1", "P4.2"], "iso27001": [], "iso27017": [], "iso27018": ["A.1.1", "A.2.2"], "nist_csf": [], "nist_800_53": ["IP-1", "IP-2", "IP-3", "IP-4"], "fedramp": ["IP-1", "IP-2", "IP-3", "IP-4"], "pci_dss": [], "hipaa": ["§164.524", "§164.526"], "gdpr": ["Art. 15", "Art. 16", "Art. 17", "Art. 18", "Art. 20", "Art. 21"], "ccpa": ["§1798.100", "§1798.105", "§1798.110"]}},
            {"id": "CCF-PRI-05", "title": "Data Minimization and Purpose Limitation", "description": "Collection limited to what is necessary for specified purposes. Not repurposed without legal basis.", "objective": "Reduce privacy risk through data minimization.", "control_type": "Administrative", "frequency": "At system design; annual review", "fedramp_delta": False, "mappings": {"soc2": ["P3.1", "P3.2"], "iso27001": [], "iso27017": [], "iso27018": ["A.2.1"], "nist_csf": [], "nist_800_53": ["PT-2", "PT-3"], "fedramp": ["PT-2", "PT-3"], "pci_dss": ["3.1"], "hipaa": ["§164.502(b)"], "gdpr": ["Art. 5(1)(b)", "Art. 5(1)(c)"], "ccpa": ["§1798.100(c)"]}},
            {"id": "CCF-PRI-06", "title": "Data Retention and Disposal", "description": "Defined retention schedules enforced. Disposal commensurate with data sensitivity.", "objective": "Data not retained beyond its useful period.", "control_type": "Operational", "frequency": "Continuous; annual retention review", "fedramp_delta": False, "mappings": {"soc2": ["P5.1", "P5.2"], "iso27001": ["A.8.10"], "iso27017": [], "iso27018": ["A.9.4.2"], "nist_csf": [], "nist_800_53": ["SI-12", "MP-6"], "fedramp": ["SI-12", "MP-6"], "pci_dss": ["3.2.1"], "hipaa": ["§164.530(j)"], "gdpr": ["Art. 5(1)(e)", "Art. 17"], "ccpa": ["§1798.105"]}},
            {"id": "CCF-PRI-07", "title": "Privacy Impact Assessments (DPIA)", "description": "DPIAs conducted for high-risk processing. Results inform processing decisions.", "objective": "Identify and mitigate privacy risks before processing.", "control_type": "Administrative", "frequency": "Prior to high-risk processing", "fedramp_delta": False, "mappings": {"soc2": ["P1.1"], "iso27001": [], "iso27017": [], "iso27018": ["A.11.3"], "nist_csf": ["GV.RM-01"], "nist_800_53": ["PT-5", "RA-8"], "fedramp": ["PT-5", "RA-8"], "pci_dss": [], "hipaa": [], "gdpr": ["Art. 35", "Art. 36"], "ccpa": ["§1798.185(a)(15)"]}},
            {"id": "CCF-PRI-08", "title": "Cross-Border Data Transfers", "description": "Appropriate safeguards for international data transfers (SCCs, BCRs, etc.).", "objective": "Lawful cross-border data transfer.", "control_type": "Administrative", "frequency": "Per transfer mechanism; annual review", "fedramp_delta": False, "mappings": {"soc2": ["P6.1"], "iso27001": [], "iso27017": [], "iso27018": ["A.11.1"], "nist_csf": [], "nist_800_53": ["PT-6"], "fedramp": ["PT-6"], "pci_dss": [], "hipaa": [], "gdpr": ["Art. 44", "Art. 45", "Art. 46"], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: DGV - Data Governance
    # =========================================================================
    {
        "id": "DGV",
        "name": "Data Governance",
        "description": "Controls governing data integrity, quality, and protection.",
        "controls": [
            {"id": "CCF-DGV-01", "title": "Data Integrity Controls", "description": "Controls ensuring accuracy, completeness, and consistency of data during processing. Validation, checksums, and reconciliation.", "objective": "Ensure data accuracy throughout processing.", "control_type": "Technical", "frequency": "Continuous", "fedramp_delta": False, "mappings": {"soc2": ["PI1.1", "PI1.2"], "iso27001": ["A.8.11"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.DS-06"], "nist_800_53": ["SI-7", "SI-7(1)", "SI-10"], "fedramp": ["SI-7", "SI-7(1)", "SI-10"], "pci_dss": [], "hipaa": ["§164.312(c)(1)"], "gdpr": ["Art. 5(1)(d)"], "ccpa": []}},
            {"id": "CCF-DGV-02", "title": "Data Loss Prevention", "description": "DLP controls to detect and prevent unauthorized exfiltration across email, web, cloud, endpoints, and APIs.", "objective": "Prevent unauthorized data disclosure.", "control_type": "Technical", "frequency": "Continuous", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC6.7"], "iso27001": ["A.8.10", "A.8.11", "A.8.12"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.DS-01", "PR.DS-02"], "nist_800_53": ["SC-7", "SI-4"], "fedramp": ["SC-7", "SI-4"], "pci_dss": [], "hipaa": ["§164.312(e)(1)"], "gdpr": ["Art. 32(1)"], "ccpa": ["§1798.150(a)"]}},
            {"id": "CCF-DGV-03", "title": "Data Masking and Anonymization", "description": "Masking, anonymization, or pseudonymization for sensitive data in non-production, analytics, and reporting.", "objective": "Reduce sensitive data exposure.", "control_type": "Technical", "frequency": "Per data provisioning; annual review", "fedramp_delta": False, "mappings": {"soc2": ["C1.1"], "iso27001": ["A.8.11"], "iso27017": [], "iso27018": ["A.10.1"], "nist_csf": ["PR.DS-01"], "nist_800_53": ["SI-19"], "fedramp": ["SI-19"], "pci_dss": ["3.4"], "hipaa": ["§164.514"], "gdpr": ["Art. 25(1)"], "ccpa": ["§1798.145(a)(5)"]}}
        ]
    },

    # =========================================================================
    # DOMAIN: CMP - Compliance and Audit
    # =========================================================================
    {
        "id": "CMP",
        "name": "Compliance and Audit",
        "description": "Controls governing compliance monitoring, audit, and continuous improvement.",
        "controls": [
            {"id": "CCF-CMP-01", "title": "Internal Audit Program", "description": "Independent internal audits on a risk-based schedule. Findings tracked to remediation.", "objective": "Independent assurance of control effectiveness.", "control_type": "Administrative", "frequency": "Annual audit plan; per schedule", "fedramp_delta": False, "mappings": {"soc2": ["CC4.1", "CC4.2"], "iso27001": ["A.5.35", "A.5.36"], "iso27017": [], "iso27018": [], "nist_csf": ["GV.OV-02"], "nist_800_53": ["CA-2", "CA-2(1)", "CA-7"], "fedramp": ["CA-2", "CA-2(1)", "CA-7"], "pci_dss": ["12.4.2"], "hipaa": ["§164.308(a)(8)"], "gdpr": ["Art. 5(2)"], "ccpa": []}},
            {"id": "CCF-CMP-02", "title": "External Audit and Certification Management", "description": "Manage external audits and certifications through structured preparation, evidence collection, and findings remediation.", "objective": "Obtain independent security assurance.", "control_type": "Administrative", "frequency": "Annual per certification cycle", "fedramp_delta": False, "mappings": {"soc2": ["CC4.1"], "iso27001": ["A.5.35"], "iso27017": [], "iso27018": [], "nist_csf": ["GV.OV-02"], "nist_800_53": ["CA-2", "CA-6"], "fedramp": ["CA-2", "CA-6"], "pci_dss": ["12.4.1"], "hipaa": ["§164.308(a)(8)"], "gdpr": ["Art. 42"], "ccpa": []}},
            {"id": "CCF-CMP-03", "title": "POA&M Management", "description": "The organization maintains a Plan of Action and Milestones (POA&M) that documents known weaknesses, planned corrective actions, responsible parties, and milestones for remediation. POA&M items are reviewed and reported monthly. High-risk items are escalated to the AO. The POA&M is the authoritative tracking mechanism for all audit findings, vulnerability remediation, and control deficiencies.", "objective": "Track and manage remediation of all identified weaknesses in a structured, auditable manner.", "control_type": "Administrative", "frequency": "Monthly review and update; continuous intake of new items", "fedramp_delta": True, "mappings": {"soc2": ["CC4.2", "CC5.3"], "iso27001": ["A.5.36"], "iso27017": [], "iso27018": [], "nist_csf": ["GV.OV-03"], "nist_800_53": ["CA-5"], "fedramp": ["CA-5", "FedRAMP POA&M Template and Requirements"], "pci_dss": ["12.4.2.1"], "hipaa": ["§164.308(a)(1)(ii)(B)"], "gdpr": [], "ccpa": []}},
            {"id": "CCF-CMP-04", "title": "Continuous Monitoring Program", "description": "The organization implements a continuous monitoring program aligned with FedRAMP ConMon requirements. The program includes ongoing assessment of security controls, vulnerability scanning, configuration monitoring, and monthly/annual reporting deliverables to the AO and FedRAMP PMO.", "objective": "Maintain ongoing authorization through continuous security assessment and reporting.", "control_type": "Technical", "frequency": "Continuous; monthly ConMon deliverables; annual assessment", "fedramp_delta": True, "mappings": {"soc2": ["CC4.1", "CC4.2"], "iso27001": ["A.5.36"], "iso27017": [], "iso27018": [], "nist_csf": ["GV.OV-01", "DE.CM-01"], "nist_800_53": ["CA-7", "CA-7(1)", "PM-14", "PM-31"], "fedramp": ["CA-7", "CA-7(1)", "PM-14", "PM-31", "FedRAMP ConMon Requirements"], "pci_dss": ["10.7", "12.4.2"], "hipaa": ["§164.308(a)(8)"], "gdpr": ["Art. 32(1)(d)"], "ccpa": []}}
        ]
    },

    # =========================================================================
    # DOMAIN: EDP - Endpoint Security (same as commercial)
    # =========================================================================
    {
        "id": "EDP",
        "name": "Endpoint Security",
        "description": "Controls for endpoint device security.",
        "controls": [
            {"id": "CCF-EDP-01", "title": "Endpoint Protection and Management", "description": "MDM/UEM deployed on all corporate endpoints enforcing security configurations including disk encryption, screen lock, OS updates, and firewall.", "objective": "Minimum security requirements for all endpoints.", "control_type": "Technical", "frequency": "Continuous; monthly compliance reporting", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC6.8"], "iso27001": ["A.8.1"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.IR-01"], "nist_800_53": ["CM-6", "SC-28"], "fedramp": ["CM-6", "SC-28"], "pci_dss": ["5.2"], "hipaa": ["§164.310(c)"], "gdpr": ["Art. 32(1)"], "ccpa": []}},
            {"id": "CCF-EDP-02", "title": "Endpoint Data Encryption", "description": "Full-disk encryption using FIPS-validated modules on all endpoints. Compliance verified automatically.", "objective": "Protect endpoint data from unauthorized access.", "control_type": "Technical", "frequency": "Continuous enforcement", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1", "CC6.7"], "iso27001": ["A.8.24"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.DS-01"], "nist_800_53": ["SC-28"], "fedramp": ["SC-28", "FIPS 140-2"], "pci_dss": ["3.5.1"], "hipaa": ["§164.312(a)(2)(iv)"], "gdpr": ["Art. 32(1)(a)"], "ccpa": []}},
            {"id": "CCF-EDP-03", "title": "Mobile Device Security", "description": "MDM enrollment, passcode enforcement, remote wipe capability, and corporate data containerization.", "objective": "Secure mobile access to corporate data.", "control_type": "Technical", "frequency": "Continuous; annual BYOD review", "fedramp_delta": False, "mappings": {"soc2": ["CC6.1"], "iso27001": ["A.8.1"], "iso27017": [], "iso27018": [], "nist_csf": ["PR.AA-03"], "nist_800_53": ["AC-19", "AC-19(5)"], "fedramp": ["AC-19", "AC-19(5)"], "pci_dss": [], "hipaa": ["§164.310(c)"], "gdpr": ["Art. 32(1)"], "ccpa": []}}
        ]
    }
]


# =============================================================================
# OUTPUT GENERATION
# =============================================================================

def build_ccf():
    return {"metadata": METADATA, "domains": DOMAINS}


def write_json(ccf, path):
    with open(path, 'w') as f:
        json.dump(ccf, f, indent=2)
    print(f"JSON: {path}")


def write_csv(ccf, path):
    frameworks = list(METADATA["frameworks"].keys())
    headers = [
        "domain_id", "domain_name", "control_id", "title", "description",
        "objective", "control_type", "frequency", "fedramp_delta"
    ] + [f"mapping_{fw}" for fw in frameworks]

    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for domain in ccf["domains"]:
            for control in domain["controls"]:
                row = [
                    domain["id"], domain["name"], control["id"], control["title"],
                    control["description"], control["objective"], control["control_type"],
                    control["frequency"], control.get("fedramp_delta", False)
                ]
                for fw in frameworks:
                    row.append("; ".join(control.get("mappings", {}).get(fw, [])))
                writer.writerow(row)
    print(f"CSV: {path}")


def write_fedramp_parameters(path):
    """Generate the FedRAMP-specific parameter values and additional requirements file."""
    params = {
        "metadata": {
            "title": "FedRAMP High Baseline — Organization-Defined Parameters (ODPs) and Additional Requirements",
            "description": (
                "FedRAMP defines specific parameter values (ODPs) for many NIST 800-53 controls. "
                "This file captures the key FedRAMP-specified values that CSPs must implement. "
                "These are NOT optional — FedRAMP auditors (3PAOs) will test against these exact values."
            ),
            "version": "FedRAMP High Rev 5",
            "last_updated": date.today().isoformat(),
            "reference": "https://www.fedramp.gov/documents/"
        },
        "parameters": [
            {"control": "AC-2", "parameter": "Account inactivity", "fedramp_value": "90 days", "notes": "Accounts inactive for 90 days must be automatically disabled."},
            {"control": "AC-2(1)", "parameter": "Automated account management", "fedramp_value": "Required", "notes": "Automated mechanisms to support account management."},
            {"control": "AC-2(3)", "parameter": "Account disable after inactivity", "fedramp_value": "90 days", "notes": "Automatically disable accounts after 90 days of inactivity."},
            {"control": "AC-7", "parameter": "Unsuccessful login attempts", "fedramp_value": "3 attempts in 15 minutes", "notes": "Lock account for 30 minutes or until unlocked by administrator."},
            {"control": "AC-8", "parameter": "System use notification", "fedramp_value": "Required", "notes": "Must display approved use notification before login."},
            {"control": "AC-10", "parameter": "Concurrent session control", "fedramp_value": "3 sessions", "notes": "Limit number of concurrent sessions per user."},
            {"control": "AC-11", "parameter": "Session lock", "fedramp_value": "15 minutes", "notes": "Initiate session lock after 15 minutes of inactivity."},
            {"control": "AC-12", "parameter": "Session termination", "fedramp_value": "30 minutes", "notes": "Terminate session after 30 minutes of inactivity."},
            {"control": "AC-17", "parameter": "Remote access", "fedramp_value": "Must use encrypted VPN or equivalent", "notes": "All remote access must be via encrypted channel with MFA."},
            {"control": "AC-18", "parameter": "Wireless access", "fedramp_value": "WPA2-Enterprise minimum", "notes": "All wireless must use enterprise-grade encryption."},
            {"control": "AT-2", "parameter": "Security awareness training", "fedramp_value": "Annual + within 60 days of hire", "notes": "All users within 60 days of initial access, annually thereafter."},
            {"control": "AT-3", "parameter": "Role-based security training", "fedramp_value": "Annual + within 60 days of role assignment", "notes": "Specialized training for security-relevant roles."},
            {"control": "AU-2", "parameter": "Audit events", "fedramp_value": "FedRAMP defined event list", "notes": "Must log: successful/failed logins, privilege use, object access, policy changes, admin actions, system events."},
            {"control": "AU-3", "parameter": "Audit record content", "fedramp_value": "Date/time, event type, user ID, source, outcome, affected object", "notes": "Minimum fields for every audit record."},
            {"control": "AU-6", "parameter": "Audit review frequency", "fedramp_value": "Weekly review; real-time alerts for critical events", "notes": "Weekly review of audit logs; immediate alerting on suspicious events."},
            {"control": "AU-11", "parameter": "Audit retention", "fedramp_value": "1 year minimum; 90 days online", "notes": "Logs retained 1 year, immediately available for 90 days."},
            {"control": "CA-8", "parameter": "Penetration testing", "fedramp_value": "Annual by independent 3PAO", "notes": "Must follow FedRAMP penetration test guidance."},
            {"control": "CM-6", "parameter": "Configuration settings", "fedramp_value": "USGCB / CIS Benchmarks / STIGs", "notes": "Must use government or industry hardening baselines."},
            {"control": "CM-8", "parameter": "Asset inventory", "fedramp_value": "Updated at least monthly", "notes": "Component inventory updated at least monthly; automated where possible."},
            {"control": "CP-3", "parameter": "Contingency training", "fedramp_value": "Within 10 days of role + annually", "notes": "Contingency plan training for designated personnel."},
            {"control": "CP-4", "parameter": "Contingency plan testing", "fedramp_value": "Annual", "notes": "Annual functional testing or tabletop exercise."},
            {"control": "IA-2", "parameter": "Multi-factor authentication", "fedramp_value": "Required for all privileged and non-privileged access", "notes": "MFA for all users; phishing-resistant for privileged."},
            {"control": "IA-5(1)", "parameter": "Password complexity", "fedramp_value": "Case sensitive, min 12 chars, 1 upper, 1 lower, 1 digit, 1 special", "notes": "Or use NIST 800-63B memorized secret guidance."},
            {"control": "IR-6", "parameter": "Incident reporting", "fedramp_value": "US-CERT within 1 hour of determination", "notes": "Report to US-CERT/CISA within 1 hour for categories per FedRAMP ICP."},
            {"control": "PS-3", "parameter": "Personnel screening", "fedramp_value": "Commensurate with position sensitivity", "notes": "National agency check minimum; higher for elevated positions."},
            {"control": "RA-5", "parameter": "Vulnerability scanning", "fedramp_value": "Monthly OS/infra; monthly web app; annual pen test", "notes": "Monthly authenticated scans; results reported in ConMon deliverables."},
            {"control": "SC-7", "parameter": "Boundary protection", "fedramp_value": "Deny by default; allow by exception", "notes": "All boundary traffic denied unless explicitly permitted."},
            {"control": "SC-13", "parameter": "Cryptographic protection", "fedramp_value": "FIPS 140-2 (or 140-3) validated modules", "notes": "Non-FIPS-validated modules prohibited for federal data."},
            {"control": "SC-28", "parameter": "Data at rest protection", "fedramp_value": "FIPS-validated encryption (AES-256)", "notes": "All federal data encrypted at rest using FIPS modules."},
            {"control": "SI-2", "parameter": "Flaw remediation", "fedramp_value": "Critical: 30 days, High: 60 days, Moderate: 90 days", "notes": "Patch timelines from identification/disclosure."},
            {"control": "SI-4", "parameter": "System monitoring", "fedramp_value": "Continuous; 24/7 for High", "notes": "Real-time monitoring with alerting capability."}
        ],
        "fedramp_additional_requirements": [
            {
                "requirement": "Continuous Monitoring (ConMon)",
                "description": "Monthly vulnerability scan results and POA&M updates submitted to FedRAMP PMO. Annual security assessment by 3PAO. Significant Change Requests (SCRs) submitted for boundary changes.",
                "deliverables": ["Monthly vulnerability scan reports", "Monthly POA&M updates", "Annual assessment report", "Significant Change Requests", "Incident reports per ICP"]
            },
            {
                "requirement": "FedRAMP Authorization Boundary",
                "description": "The CSP must clearly define and document the authorization boundary in the SSP, including all components, data flows, interconnections, and inherited controls. The boundary must be approved by the AO.",
                "deliverables": ["SSP Section 9", "Network diagrams", "Data flow diagrams"]
            },
            {
                "requirement": "Integrated Inventory Workbook",
                "description": "Maintain an integrated inventory workbook listing all hardware, software, and interconnections within the authorization boundary per FedRAMP template.",
                "deliverables": ["FedRAMP Integrated Inventory Workbook"]
            },
            {
                "requirement": "Digital Identity Requirements",
                "description": "Authentication aligns with NIST SP 800-63 Digital Identity Guidelines. AAL2 minimum for all users; AAL3 recommended for privileged access at High.",
                "deliverables": ["Digital Identity Determination documented in SSP"]
            },
            {
                "requirement": "FIPS 199 Categorization",
                "description": "System categorized per FIPS 199 and FIPS 200. For FedRAMP High, the system impact level is High for one or more of confidentiality, integrity, or availability.",
                "deliverables": ["FIPS 199 Categorization in SSP"]
            }
        ]
    }

    with open(path, 'w') as f:
        json.dump(params, f, indent=2)
    print(f"FedRAMP Parameters: {path}")


def print_stats(ccf):
    total_controls = sum(len(d["controls"]) for d in ccf["domains"])
    delta_controls = sum(1 for d in ccf["domains"] for c in d["controls"] if c.get("fedramp_delta"))
    base_controls = total_controls - delta_controls
    frameworks = list(METADATA["frameworks"].keys())

    print(f"\n{'='*60}")
    print(f"OpenCCF FedRAMP/Gov Edition v{METADATA['version']}")
    print(f"{'='*60}")
    print(f"Total Domains:       {len(ccf['domains'])}")
    print(f"Total Controls:      {total_controls}")
    print(f"  From Commercial:   {base_controls}")
    print(f"  FedRAMP Additions: {delta_controls}")
    print(f"Frameworks Mapped:   {len(frameworks)}")
    print()
    for domain in ccf["domains"]:
        ctrl_count = len(domain["controls"])
        delta_count = sum(1 for c in domain["controls"] if c.get("fedramp_delta"))
        delta_str = f" (+{delta_count} FedRAMP)" if delta_count else ""
        print(f"  {domain['id']:5s} - {domain['name']:45s} [{ctrl_count:3d} controls{delta_str}]")

    total_mappings = sum(
        len(c.get("mappings", {}).get(fw, []))
        for d in ccf["domains"] for c in d["controls"] for fw in frameworks
    )
    print(f"\nTotal Cross-Framework Mappings: {total_mappings}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    output_dir = "/mnt/user-data/outputs/fedramp"
    os.makedirs(output_dir, exist_ok=True)

    ccf = build_ccf()
    print_stats(ccf)

    write_json(ccf, os.path.join(output_dir, "openccf-fedramp.json"))
    write_csv(ccf, os.path.join(output_dir, "openccf-fedramp.csv"))
    write_fedramp_parameters(os.path.join(output_dir, "fedramp-parameters.json"))

    print("\nGeneration complete.")
