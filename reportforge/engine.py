import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor
from .enrichment import clean_xml_string
from .parser import FindingItem
from .registry import PresetConfig
from .template_builder import TemplateBuilder


class DocxEngine:
    """
    Populates CSIRT and VDP .docx templates with deterministic formatting,
    multi-finding table generation, and custom template compatibility.
    """

    FONT_NAME = "Times New Roman"
    BLACK = RGBColor(0, 0, 0)

    BRACKET_REGEX_RULES = [
        (re.compile(r"\[ASET\.[A-Z0-9.\-_]+\]"), "{{ASSET_HEADER}}"),
        (re.compile(r"\[aset\.[a-z0-9.\-_]+\]\s*\[[0-9.]+\]"), "{{DOMAIN_IP}}"),
        (re.compile(r"\[aset\.[a-z0-9.\-_/:]+\]"), "{{URL_ENDPOINT}}"),
    ]

    @classmethod
    def _unwrap_sdt_elements(cls, doc: Any) -> None:
        """Promotes tables and paragraphs inside <w:sdt><w:sdtContent> directly to <w:body>."""
        body = doc.element.body
        for sdt in list(body.iter(qn("w:sdt"))):
            parent = sdt.getparent()
            if parent is None:
                continue
            sdt_content = sdt.find(qn("w:sdtContent"))
            if sdt_content is not None:
                for child in list(sdt_content):
                    sdt.addprevious(child)
            parent.remove(sdt)

    @classmethod
    def _strip_cover_drawings(cls, doc: Any) -> None:
        """Removes decorative clip-art drawings so generated reports remain clean."""
        for p in doc.paragraphs:
            for drawing in list(p._p.iter(qn("w:drawing"))):
                parent = drawing.getparent()
                if parent is not None:
                    parent.remove(drawing)

    @classmethod
    def _replace_in_paragraph(cls, paragraph: Any, replacements: Dict[str, str]) -> None:
        full_text = paragraph.text
        if not full_text:
            return

        updated = full_text
        for pattern, placeholder_key in cls.BRACKET_REGEX_RULES:
            if pattern.search(updated):
                updated = pattern.sub(placeholder_key, updated)

        has_target = (updated != full_text) or any(k in updated for k in replacements)
        if not has_target:
            return

        for k, v in replacements.items():
            if k in updated:
                updated = updated.replace(k, clean_xml_string(v))

        p_align = paragraph.alignment
        runs_count = len(paragraph.runs)
        first_font_size = paragraph.runs[0].font.size if runs_count > 0 else Pt(12)
        first_bold = paragraph.runs[0].font.bold if runs_count > 0 else False
        first_italic = paragraph.runs[0].font.italic if runs_count > 0 else False

        for r in paragraph.runs[1:]:
            r.text = ""

        if paragraph.runs:
            paragraph.runs[0].text = updated
            paragraph.runs[0].font.name = cls.FONT_NAME
            if first_font_size:
                paragraph.runs[0].font.size = first_font_size
            paragraph.runs[0].font.bold = first_bold
            paragraph.runs[0].font.italic = first_italic
            paragraph.runs[0].font.color.rgb = cls.BLACK
        else:
            r = paragraph.add_run(updated)
            r.font.name = cls.FONT_NAME
            r.font.size = Pt(12)
            r.font.color.rgb = cls.BLACK

        paragraph.alignment = p_align
        paragraph.paragraph_format.line_spacing = 1.15

    @classmethod
    def _replace_in_table(cls, table: Any, replacements: Dict[str, str]) -> None:
        for row in table.rows:
            for cell in row.cells:
                for p in cell.paragraphs:
                    cls._replace_in_paragraph(p, replacements)
                for nested in cell.tables:
                    cls._replace_in_table(nested, replacements)

    @classmethod
    def _populate_tables_by_label(cls, doc: Any, row_label_map: Dict[str, str]) -> None:
        """Populates two-column tables by matching left-column field labels."""
        for tbl in doc.tables:
            if len(tbl.columns) != 2:
                continue
            for row in tbl.rows:
                label = row.cells[0].text.strip().lower()
                if label in row_label_map:
                    val_cell = row.cells[1]
                    val_text = clean_xml_string(row_label_map[label])
                    for p in val_cell.paragraphs[1:]:
                        p.text = ""
                    p0 = val_cell.paragraphs[0]
                    for r in p0.runs[1:]:
                        r.text = ""
                    if p0.runs:
                        p0.runs[0].text = val_text
                        p0.runs[0].font.name = cls.FONT_NAME
                        p0.runs[0].font.size = Pt(12)
                        p0.runs[0].font.bold = False
                        p0.runs[0].font.color.rgb = cls.BLACK
                    else:
                        r = p0.add_run(val_text)
                        r.font.name = cls.FONT_NAME
                        r.font.size = Pt(12)
                        r.font.color.rgb = cls.BLACK
                    p0.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY

    @classmethod
    def replace_all_placeholders(cls, doc: Any, replacements: Dict[str, str]) -> None:
        for p in doc.paragraphs:
            cls._replace_in_paragraph(p, replacements)
        for tbl in doc.tables:
            cls._replace_in_table(tbl, replacements)

    @classmethod
    def format_all_tables_monochrome(cls, doc: Any) -> None:
        for tbl in doc.tables:
            tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            if len(tbl.rows) == 1 and len(tbl.columns) == 1:
                TemplateBuilder.set_table_borderless(tbl)
            else:
                TemplateBuilder.set_table_borders_black(tbl, sz="4")
            for row in tbl.rows:
                for cell in row.cells:
                    TemplateBuilder.clear_cell_shading(cell)
                    TemplateBuilder.set_cell_margins(cell, top=90, bottom=90, left=120, right=120)
                    for p in cell.paragraphs:
                        for run in p.runs:
                            run.font.name = cls.FONT_NAME
                            run.font.color.rgb = cls.BLACK

    @classmethod
    def format_all_paragraphs_academic(cls, doc: Any) -> None:
        for p in doc.paragraphs:
            if p.alignment != WD_ALIGN_PARAGRAPH.CENTER:
                p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.paragraph_format.line_spacing = 1.15
            for r in p.runs:
                r.font.name = cls.FONT_NAME
                r.font.color.rgb = cls.BLACK

    @classmethod
    def _insert_additional_findings(
        cls,
        doc: Any,
        extra_findings: List[FindingItem],
        effective_asset: str,
        effective_asset_type: str,
        effective_domain_ip: str,
        effective_app_ver: str,
    ) -> None:
        anchor_p = None
        is_marker = False
        for p in doc.paragraphs:
            if "{{ADDITIONAL_FINDINGS_SECTION}}" in p.text:
                anchor_p = p
                is_marker = True
                break

        if anchor_p is None:
            for p in doc.paragraphs:
                if p.text.strip().lower() in ("conclusion", "kesimpulan"):
                    anchor_p = p
                    break

        if not extra_findings:
            if anchor_p is not None and is_marker:
                parent = anchor_p._p.getparent()
                if parent is not None:
                    parent.remove(anchor_p._p)
            return

        def attach_before_anchor(element_xml: Any) -> None:
            if anchor_p is not None:
                anchor_p._p.addprevious(element_xml)

        for idx, extra_f in enumerate(extra_findings, 2):
            p_break = doc.add_paragraph()
            p_break.add_run().add_break()
            attach_before_anchor(p_break._p)

            h_extra = TemplateBuilder.add_formatted_paragraph(
                doc,
                text=f"Vulnerability Details — Finding {idx}: {extra_f.title}",
                size_pt=14,
                bold=True,
                align=WD_ALIGN_PARAGRAPH.JUSTIFY,
                space_before=10,
                space_after=6,
                style_name="Heading 1",
            )
            attach_before_anchor(h_extra._p)

            extra_rows = [
                ("Vulnerability Title", extra_f.title),
                ("Category (OWASP/CWE/CVE)", extra_f.cwe_id),
                ("Affected Asset", extra_f.asset_name or effective_asset),
                ("Asset Type", extra_f.asset_type or effective_asset_type),
                ("Domain/IP", extra_f.domain_ip or effective_domain_ip),
                ("URL/Endpoint", extra_f.endpoint),
                ("Application Version", extra_f.app_version or effective_app_ver),
                ("Severity", extra_f.severity_label),
                ("CVSS Score", f"{extra_f.cvss_score:.1f}"),
                ("Vulnerability Description", extra_f.description),
                ("Impact", extra_f.impact),
                ("Remediation Recommendation", extra_f.remediation_summary),
                ("References", extra_f.references),
            ]
            tbl_extra = doc.add_table(rows=len(extra_rows), cols=2)
            TemplateBuilder.populate_two_col_table(tbl_extra, extra_rows)
            attach_before_anchor(tbl_extra._tbl)

            h_steps = TemplateBuilder.add_formatted_paragraph(
                doc,
                text="Steps to Reproduce",
                size_pt=12,
                bold=True,
                align=WD_ALIGN_PARAGRAPH.JUSTIFY,
                space_before=12,
                space_after=4,
                style_name="Heading 3",
            )
            attach_before_anchor(h_steps._p)

            steps_str = (
                "\n".join(f"{s_i}. {s_t}" for s_i, s_t in enumerate(extra_f.steps_to_reproduce, 1))
                if extra_f.steps_to_reproduce
                else "1. No specific reproduction steps provided."
            )
            p_steps = TemplateBuilder.add_formatted_paragraph(
                doc,
                text=steps_str,
                size_pt=12,
                align=WD_ALIGN_PARAGRAPH.JUSTIFY,
                space_before=0,
                space_after=8,
            )
            attach_before_anchor(p_steps._p)

            h_poc = TemplateBuilder.add_formatted_paragraph(
                doc,
                text="Proof of Concept",
                size_pt=12,
                bold=True,
                align=WD_ALIGN_PARAGRAPH.JUSTIFY,
                space_before=10,
                space_after=4,
                style_name="Heading 3",
            )
            attach_before_anchor(h_poc._p)

            poc_sub = []
            if extra_f.redacted_request:
                poc_sub.append("--- Sanitized HTTP Request Evidence ---\n" + extra_f.redacted_request)
            if extra_f.redacted_response:
                poc_sub.append("--- Sanitized HTTP Response Evidence ---\n" + extra_f.redacted_response)
            if extra_f.remediation_code:
                poc_sub.append("--- Recommended Code Patch (DevFixer Blueprint) ---\n" + extra_f.remediation_code)

            p_poc = TemplateBuilder.add_formatted_paragraph(
                doc,
                text="\n\n".join(poc_sub) if poc_sub else "Sanitized Proof of Concept (PoC) evidence is attached.",
                size_pt=11,
                align=WD_ALIGN_PARAGRAPH.LEFT,
                space_before=0,
                space_after=10,
            )
            attach_before_anchor(p_poc._p)

        if anchor_p is not None and is_marker:
            parent = anchor_p._p.getparent()
            if parent is not None:
                parent.remove(anchor_p._p)

    @classmethod
    def populate(
        cls,
        template_path: Path,
        findings: List[FindingItem],
        config: PresetConfig,
        participant_name: str,
        participant_alias: str,
        asset_name: str,
        asset_type: str,
        domain_ip: str,
        app_version: str,
        contact_person: str,
        output_path: Path,
    ) -> Path:
        doc = Document(str(template_path))
        cls._unwrap_sdt_elements(doc)
        cls._strip_cover_drawings(doc)

        lead = findings[0] if findings else None
        now_dt = datetime.now(timezone.utc)
        date_str_short = now_dt.strftime("%d-%m-%Y")
        date_str_long = f"[{now_dt.strftime('%d %B %Y')}]"

        effective_asset = asset_name or (lead.asset_name if lead and lead.asset_name else config.default_asset_name)
        effective_domain_ip = domain_ip or (lead.domain_ip if lead and lead.domain_ip else config.default_domain_ip)
        effective_asset_type = asset_type or (lead.asset_type if lead and lead.asset_type else config.default_asset_type)
        effective_app_ver = app_version or (lead.app_version if lead and lead.app_version else config.default_app_version)
        effective_contact = contact_person or config.contact_email

        domain_only = effective_domain_ip.split("/")[0].strip().upper()
        if not domain_only.startswith("["):
            domain_only = f"[{domain_only}]"

        steps_rendered = "1. No specific reproduction steps provided."
        if lead and lead.steps_to_reproduce:
            steps_rendered = "\n".join(f"{idx}. {step}" for idx, step in enumerate(lead.steps_to_reproduce, 1))

        poc_parts = []
        if lead and lead.redacted_request:
            poc_parts.append("--- Sanitized HTTP Request Evidence ---\n" + lead.redacted_request)
        if lead and lead.redacted_response:
            poc_parts.append("--- Sanitized HTTP Response Evidence ---\n" + lead.redacted_response)
        if lead and lead.remediation_code:
            poc_parts.append("--- Recommended Code Patch (DevFixer Blueprint) ---\n" + lead.remediation_code)
        poc_rendered = "\n\n".join(poc_parts) if poc_parts else "Sanitized Proof of Concept (PoC) evidence is attached in the assessment repository."

        crit_count = sum(1 for f in findings if f.severity_label == "Critical")
        high_count = sum(1 for f in findings if f.severity_label == "High")
        med_count = sum(1 for f in findings if f.severity_label == "Medium")
        low_count = sum(1 for f in findings if f.severity_label in ("Low", "Informational"))

        overall_risk = "Critical" if crit_count > 0 else ("High" if high_count > 0 else "Medium")
        kesimpulan_text = (
            f"Based on the controlled security assessment conducted against {effective_asset} ({effective_domain_ip}), "
            f"a total of {len(findings)} valid security findings were identified: {crit_count} Critical, "
            f"{high_count} High, {med_count} Medium, and {low_count} Low/Informational. "
            f"The overall risk posture affecting system confidentiality and integrity is rated as {overall_risk}. "
            f"Immediate remediation priority should be directed toward resolving {lead.title if lead else 'the primary finding'} "
            f"in accordance with the provided technical remediation blueprints prior to production deployment."
        )

        # Normalize ellipsis (...) placeholders under Steps to Reproduce in custom templates
        ellipsis_seen = False
        for p in list(doc.paragraphs):
            if p.text.strip() in ("…", "..."):
                if not ellipsis_seen:
                    p.text = "{{STEPS_TO_REPRODUCE}}"
                    ellipsis_seen = True
                else:
                    parent = p._p.getparent()
                    if parent is not None:
                        parent.remove(p._p)

        replacements = {
            "{{REPORT_TITLE}}": "VULNERABILITY DISCLOSURE PROGRAM ASSESSMENT REPORT",
            "{{ASSET_HEADER}}": domain_only,
            "{{PROGRAM_BANNER}}": config.program_banner,
            "{{REPORT_DATE_LONG}}": date_str_long,
            "{{NAMA_PESERTA}}": participant_name,
            "{{NAMA_ALIAS}}": participant_alias,
            "{{TANGGAL_PENGUJIAN}}": date_str_short,
            "{{NAMA_ASET}}": effective_asset,
            "{{JENIS_ASET}}": effective_asset_type,
            "{{DOMAIN_IP}}": effective_domain_ip,
            "{{VERSI_APLIKASI}}": effective_app_ver,
            "{{KONTAK_PJ}}": effective_contact,
            "{{ORG_NAME}}": config.organization_name,
            "{{JUDUL_KERENTANAN}}": lead.title if lead else "No Findings Identified",
            "{{KATEGORI_KERENTANAN}}": lead.cwe_id if lead else "N/A",
            "{{URL_ENDPOINT}}": lead.endpoint if lead else "-",
            "{{SEVERITY}}": lead.severity_label if lead else "Informational",
            "{{CVSS_SCORE}}": f"{lead.cvss_score:.1f}" if lead else "0.0",
            "{{DESKRIPSI_KERENTANAN}}": lead.description if lead else "-",
            "{{DAMPAK_KERENTANAN}}": lead.impact if lead else "-",
            "{{REKOMENDASI_PERBAIKAN}}": lead.remediation_summary if lead else "-",
            "{{REFERENSI}}": lead.references if lead else "OWASP Top 10, MITRE CWE",
            "{{STEPS_TO_REPRODUCE}}": steps_rendered,
            "{{POC_EVIDENCE}}": poc_rendered,
            "{{KESIMPULAN_PARAGRAF}}": kesimpulan_text,
            "[20 September 2026]": date_str_long.strip("[]"),
            "Tempelkan screenshot atau bukti eksploitasi di bawah bagian ini.": poc_rendered,
            "Kesimpulan berisikan keseluruhan hasil pengujian, tingkat risiko, dan prioritas perbaikan.": kesimpulan_text,
        }

        # Supports both English built-in templates and custom uploaded CSIRT templates
        row_label_map = {
            "participant name": participant_name,
            "nama peserta": participant_name,
            "participant alias": participant_alias,
            "nama alias": participant_alias,
            "assessment date": date_str_short,
            "tanggal pengujian": date_str_short,
            "asset name": effective_asset,
            "nama aset": effective_asset,
            "asset type": effective_asset_type,
            "jenis aset": effective_asset_type,
            "domain/ip": effective_domain_ip,
            "application version": effective_app_ver,
            "versi aplikasi (jika diketahui)": effective_app_ver,
            "point of contact": effective_contact,
            "kontak penanggung jawab (opsional)": effective_contact,
            "vulnerability title": lead.title if lead else "No Findings Identified",
            "judul kerentanan": lead.title if lead else "No Findings Identified",
            "category (owasp/cwe/cve)": lead.cwe_id if lead else "N/A",
            "kategori (owasp/cwe/cve bila ada)": lead.cwe_id if lead else "N/A",
            "affected asset": effective_asset,
            "aset terdampak": effective_asset,
            "url/endpoint": lead.endpoint if lead else "-",
            "severity": lead.severity_label if lead else "Informational",
            "cvss score": f"{lead.cvss_score:.1f}" if lead else "0.0",
            "vulnerability description": lead.description if lead else "-",
            "deskripsi kerentanan": lead.description if lead else "-",
            "impact": lead.impact if lead else "-",
            "dampak": lead.impact if lead else "-",
            "remediation recommendation": lead.remediation_summary if lead else "-",
            "rekomendasi perbaikan": lead.remediation_summary if lead else "-",
            "references": lead.references if lead else "OWASP Top 10, MITRE CWE",
            "referensi": lead.references if lead else "OWASP Top 10, MITRE CWE",
        }

        cls.replace_all_placeholders(doc, replacements)
        cls._populate_tables_by_label(doc, row_label_map)
        cls._insert_additional_findings(
            doc,
            findings[1:] if len(findings) > 1 else [],
            effective_asset,
            effective_asset_type,
            effective_domain_ip,
            effective_app_ver,
        )
        cls.format_all_tables_monochrome(doc)
        cls.format_all_paragraphs_academic(doc)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc.save(str(output_path))
        return output_path

    @classmethod
    def to_markdown(
        cls,
        findings: List[FindingItem],
        config: PresetConfig,
        participant_name: str,
        participant_alias: str,
        asset_name: str,
        domain_ip: str,
    ) -> str:
        lead = findings[0] if findings else None
        now_dt = datetime.now(timezone.utc)
        lines = [
            "# VULNERABILITY DISCLOSURE PROGRAM ASSESSMENT REPORT",
            f"## [{domain_ip.split('/')[0].strip().upper()}]",
            "",
            f"**Program:** {config.program_banner}  ",
            f"**Assessment Date:** {now_dt.strftime('%d-%m-%Y')}  ",
            f"**Researcher:** {participant_name} (`{participant_alias}`)  ",
            f"**Target Organization:** {config.organization_name}",
            "",
            "---",
            "",
            "## 1. General Information",
            "",
            "| Attribute | Value |",
            "| :--- | :--- |",
            f"| **Participant Name** | {participant_name} |",
            f"| **Participant Alias** | {participant_alias} |",
            f"| **Assessment Date** | {now_dt.strftime('%d-%m-%Y')} |",
            f"| **Asset Name** | {asset_name} |",
            f"| **Asset Type** | Website / API / Server |",
            f"| **Domain/IP** | {domain_ip} |",
            f"| **Application Version** | v2.1 |",
            f"| **Point of Contact** | {config.contact_email} |",
            "",
            f"> *All data obtained during this assessment is kept strictly confidential and is used exclusively for the {config.organization_name} Vulnerability Disclosure Program.*",
            "",
            "---",
            "",
            "## 2. Vulnerability Details",
            "",
        ]

        for idx, f in enumerate(findings, 1):
            lines.extend(
                [
                    f"### Finding {idx}: {f.title}",
                    "",
                    "| Field | Details |",
                    "| :--- | :--- |",
                    f"| **Vulnerability Title** | {f.title} |",
                    f"| **Category (CWE/OWASP)** | {f.cwe_id} |",
                    f"| **Affected Asset** | {asset_name} |",
                    f"| **Asset Type** | {f.asset_type} |",
                    f"| **Domain/IP** | {domain_ip} |",
                    f"| **URL/Endpoint** | `{f.endpoint}` |",
                    f"| **Application Version** | {f.app_version} |",
                    f"| **Severity** | **{f.severity_label}** |",
                    f"| **CVSS Score** | **{f.cvss_score:.1f}** (`{f.cvss_vector}`) |",
                    f"| **Vulnerability Description** | {f.description} |",
                    f"| **Impact** | {f.impact} |",
                    f"| **Remediation Recommendation** | {f.remediation_summary} |",
                    f"| **References** | {f.references} |",
                    "",
                    "#### Steps to Reproduce",
                    "",
                ]
            )
            for s_i, st in enumerate(f.steps_to_reproduce, 1):
                lines.append(f"{s_i}. {st}")
            lines.append("")

            if f.redacted_request:
                lines.extend(["#### Proof of Concept (Sanitized HTTP Request)", "```http", f.redacted_request, "```", ""])
            if f.redacted_response:
                lines.extend(["#### Proof of Concept (Sanitized HTTP Response)", "```http", f.redacted_response, "```", ""])
            if f.remediation_code:
                lines.extend(["#### Recommended Code Patch (DevFixer Blueprint)", f"```{f.remediation_lang}", f.remediation_code, "```", ""])
            lines.extend(["---", ""])

        crit_count = sum(1 for f in findings if f.severity_label == "Critical")
        high_count = sum(1 for f in findings if f.severity_label == "High")
        med_count = sum(1 for f in findings if f.severity_label == "Medium")
        low_count = sum(1 for f in findings if f.severity_label in ("Low", "Informational"))
        overall_risk = "Critical" if crit_count > 0 else ("High" if high_count > 0 else "Medium")

        lines.extend(
            [
                "## 3. Conclusion",
                "",
                f"Based on the controlled security assessment conducted against **{asset_name}** (`{domain_ip}`), a total of **{len(findings)} valid findings** were identified ({crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low/Informational). "
                f"The overall system risk posture is rated as **{overall_risk}**. Immediate remediation priority should be directed toward patching {lead.title if lead else 'the identified vulnerabilities'} to prevent unauthorized exploitation.",
            ]
        )
        return "\n".join(lines)