import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from .enrichment import (
    CVSS31Calculator,
    HTTPSanitizer,
    RemediationLibrary,
    ScopeGuard,
    clean_xml_string,
)

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}


@dataclass
class FindingItem:
    id: str
    title: str
    endpoint: str
    vuln_type: str
    cwe_id: str
    cvss_vector: str
    cvss_score: float
    severity_label: str
    description: str
    impact: str
    status: str
    asset_name: str = ""
    asset_type: str = "Website / API / Server"
    domain_ip: str = ""
    app_version: str = "v2.1"
    references: str = ""
    in_scope: bool = True
    steps_to_reproduce: List[str] = field(default_factory=list)
    redacted_request: str = ""
    redacted_response: str = ""
    remediation_summary: str = ""
    remediation_code: str = ""
    remediation_lang: str = "text"

    def to_dict(self) -> Dict[str, Any]:
        """Exports sanitized finding dictionary with zero unsanitized credentials."""
        return {
            "id": self.id,
            "title": self.title,
            "endpoint": self.endpoint,
            "vuln_type": self.vuln_type,
            "cwe_id": self.cwe_id,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity_label": self.severity_label,
            "description": self.description,
            "impact": self.impact,
            "status": self.status,
            "asset_name": self.asset_name,
            "asset_type": self.asset_type,
            "domain_ip": self.domain_ip,
            "app_version": self.app_version,
            "references": self.references,
            "in_scope": self.in_scope,
            "steps_to_reproduce": list(self.steps_to_reproduce),
            "redacted_request": self.redacted_request,
            "redacted_response": self.redacted_response,
            "remediation_summary": self.remediation_summary,
            "remediation_code": self.remediation_code,
            "remediation_lang": self.remediation_lang,
        }


def load_findings(
    json_path: str | Path,
    scope_path: Optional[str | Path] = None,
    exclude_out_of_scope: bool = False,
) -> List[FindingItem]:
    path = Path(json_path)
    if not path.is_file():
        raise FileNotFoundError(f"Findings file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Findings file must contain a JSON Array ([...])")

    guard: Optional[ScopeGuard] = None
    if scope_path:
        sp = Path(scope_path)
        if not sp.is_file():
            raise FileNotFoundError(f"Scope configuration file not found: {sp}")
        with open(sp, "r", encoding="utf-8") as sf:
            sdata = json.load(sf)
        guard = ScopeGuard(
            in_scope=sdata.get("in_scope", ["*"]),
            out_of_scope=sdata.get("out_of_scope", []),
        )

    findings: List[FindingItem] = []
    for idx, row in enumerate(data, 1):
        if not isinstance(row, dict):
            raise ValueError(f"Finding item #{idx} must be a JSON object")

        fid = clean_xml_string(row.get("id", f"VULN-{idx:03d}"))
        title = clean_xml_string(row.get("title", "Application Security Vulnerability"))
        endpoint = clean_xml_string(row.get("endpoint", "-"))
        vuln_type = clean_xml_string(row.get("vuln_type", "General Flaw"))
        cvss_vector = clean_xml_string(row.get("cvss_vector", ""))
        description = clean_xml_string(row.get("description", "-"))
        impact = clean_xml_string(
            row.get("impact")
            or "Potential compromise of confidentiality, integrity, and availability of the target information system."
        )
        status = clean_xml_string(row.get("status", "OPEN"))

        raw_score = row.get("cvss_score")
        raw_label = row.get("severity_label") or row.get("severity")
        if cvss_vector and (raw_score is None or float(raw_score) == 0.0):
            cvss_score, calc_label = CVSS31Calculator.calculate(cvss_vector)
            severity_label = CVSS31Calculator.normalize_severity_label(str(raw_label or calc_label), cvss_score)
        else:
            cvss_score = float(raw_score or 0.0)
            severity_label = CVSS31Calculator.normalize_severity_label(str(raw_label or ""), cvss_score)

        if guard is not None:
            in_scope, _ = guard.validate(endpoint)
        else:
            in_scope = bool(row.get("in_scope", True))

        if exclude_out_of_scope and not in_scope:
            continue

        raw_req = row.get("redacted_request") or row.get("raw_http_request") or ""
        raw_resp = row.get("redacted_response") or row.get("raw_http_response") or ""
        redacted_request = HTTPSanitizer.sanitize_http_block(raw_req)
        redacted_response = HTTPSanitizer.sanitize_http_block(raw_resp)

        rem_blueprint = RemediationLibrary.enrich(vuln_type)
        cwe_id = clean_xml_string(row.get("cwe_id") or row.get("category") or rem_blueprint["cwe_id"])
        remediation_summary = clean_xml_string(
            row.get("remediation_summary") or row.get("remediation") or rem_blueprint["summary"]
        )
        remediation_code = clean_xml_string(
            row.get("remediation_code") or rem_blueprint["code"]
        )
        remediation_lang = clean_xml_string(
            row.get("remediation_lang") or rem_blueprint["lang"]
        )
        references = clean_xml_string(
            row.get("references") or rem_blueprint.get("references", "OWASP Top 10, MITRE CWE")
        )

        parsed_ep = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
        inferred_host = parsed_ep.hostname or ""
        domain_ip = clean_xml_string(
            row.get("domain_ip") or (f"{inferred_host} / 192.0.2.10" if inferred_host else "")
        )
        asset_name = clean_xml_string(row.get("asset_name", ""))
        asset_type = clean_xml_string(row.get("asset_type", "Website / API / Server"))
        app_version = clean_xml_string(row.get("app_version", "v2.1"))

        steps_raw = row.get("steps_to_reproduce", [])
        steps_clean = [clean_xml_string(s) for s in steps_raw if str(s).strip()]

        findings.append(
            FindingItem(
                id=fid,
                title=title,
                endpoint=endpoint,
                vuln_type=vuln_type,
                cwe_id=cwe_id,
                cvss_vector=cvss_vector,
                cvss_score=cvss_score,
                severity_label=severity_label,
                description=description,
                impact=impact,
                status=status,
                asset_name=asset_name,
                asset_type=asset_type,
                domain_ip=domain_ip,
                app_version=app_version,
                references=references,
                in_scope=in_scope,
                steps_to_reproduce=steps_clean,
                redacted_request=redacted_request,
                redacted_response=redacted_response,
                remediation_summary=remediation_summary,
                remediation_code=remediation_code,
                remediation_lang=remediation_lang,
            )
        )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity_label, 99), -f.cvss_score))
    return findings