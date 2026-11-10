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

        # 1. Format Temuan Utama (Lead Finding)
        steps_rendered = "1. Tidak ada langkah reproduksi spesifik yang dilampirkan."
        if lead and lead.steps_to_reproduce:
            steps_rendered = "\n".join(f"{idx}. {step}" for idx, step in enumerate(lead.steps_to_reproduce, 1))

        poc_parts = []
        if lead and lead.redacted_request:
            poc_parts.append("--- Bukti HTTP Request (Tersanitasi) ---\n" + lead.redacted_request)
        if lead and lead.redacted_response:
            poc_parts.append("--- Bukti HTTP Response (Tersanitasi) ---\n" + lead.redacted_response)
        if lead and lead.remediation_code:
            poc_parts.append("--- Rekomendasi Patch Kode (DevFixer Blueprint) ---\n" + lead.remediation_code)
        poc_rendered = "\n\n".join(poc_parts) if poc_parts else "Bukti Proof of Concept (PoC) tersanitasi terlampir pada repositori pengujian internal."

        crit_count = sum(1 for f in findings if f.severity_label == "Critical")
        high_count = sum(1 for f in findings if f.severity_label == "High")
        med_count = sum(1 for f in findings if f.severity_label == "Medium")
        low_count = sum(1 for f in findings if f.severity_label in ("Low", "Informational"))

        kesimpulan_text = (
            f"Berdasarkan hasil pengujian keamanan yang telah dilaksanakan secara etis dan terkoordinasi terhadap aset "
            f"{effective_asset} ({effective_domain_ip}), ditemukan sebanyak {len(findings)} kerentanan valid dengan rincian: "
            f"{crit_count} Critical, {high_count} High, {med_count} Medium, dan {low_count} Low/Informational. "
            f"Tingkat risiko sistem secara keseluruhan dinilai berada pada kategori "
            f"{'Kritis' if crit_count > 0 else ('Tinggi' if high_count > 0 else 'Sedang')} terhadap kerahasiaan dan integritas data. "
            f"Prioritas perbaikan utama disarankan difokuskan pada penambalan celah {lead.title if lead else 'utama'} "
            f"sesuai dengan rekomendasi teknis yang telah dijabarkan sebelum sistem dipublikasikan ke lingkungan produksi."
        )

        replacements = {
            "{{REPORT_TITLE}}": "LAPORAN HASIL PENGUJIAN VULNERABILITY DISCLOSURE PROGRAM",
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
            "{{JUDUL_KERENTANAN}}": lead.title if lead else "Tidak Ada Temuan",
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
            # Fallback matching template referensi
            "[ASET.BMKG.GO.ID]": domain_only,
            "[Andra Dwi Puspitasari]": participant_name,
            "[ADP777]": participant_alias,
            "[11-11-2026]": date_str_short,
            "[20 September 2026]": date_str_long.strip("[]"),
            "[SQL Injection]": lead.title if lead else "SQL Injection",
            "[CVE x]": lead.cwe_id if lead else "CWE-89",
            "[aset.bmkg.go.id] [123.45.678.9]": effective_domain_ip,
            "[aset.bmkg.go.id/login.php]": lead.endpoint if lead else effective_domain_ip,
            "[v2.1]": effective_app_ver,
            "[xxx@gmail.com] / [0812-3456-7890]": effective_contact,
            "Critical / High / Medium / Low / Informational": lead.severity_label if lead else "Medium",
            " 9.8": f" {lead.cvss_score:.1f}" if lead else " 6.5",
            "[Deskripsi mengenai kerentanan yang ditemukan secara singkat]": lead.description if lead else "-",
            "[Jelaskan dampak terhadap kerahasiaan, integritas, dan ketersediaan]": lead.impact if lead else "-",
            "[Berikan langkah mitigasi yang disarankan]": lead.remediation_summary if lead else "-",
            "[OWASP, CWE, CVE, vendor advisory, dll]": lead.references if lead else "OWASP Top 10, MITRE CWE",
            "Tempelkan screenshot atau bukti eksploitasi di bawah bagian ini.": poc_rendered,
            "Kesimpulan berisikan keseluruhan hasil pengujian, tingkat risiko, dan prioritas perbaikan.": kesimpulan_text,
        }

        # 2. Tangani Temuan Tambahan (Index 1 s/d N)
        target_p = None
        for p in doc.paragraphs:
            if "{{ADDITIONAL_FINDINGS_SECTION}}" in p.text:
                target_p = p
                break

        if target_p is not None:
            target_p.text = ""  # Bersihkan marker
            if len(findings) > 1:
                for idx, extra_f in enumerate(findings[1:], 2):
                    # Separator page break antar temuan
                    doc.add_page_break()
                    
                    # Heading Temuan Tambahan
                    h_extra = doc.add_paragraph(style="Heading 1")
                    h_extra.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                    r_h = h_extra.add_run(f"Detail Kerentanan — Temuan {idx}: {extra_f.title}")
                    r_h.font.name = cls.FONT_NAME
                    r_h.font.size = Pt(14)
                    r_h.font.bold = True
                    r_h.font.color.rgb = cls.BLACK

                    # Tabel 13 baris identik
                    extra_rows = [
                        ("Judul Kerentanan", extra_f.title),
                        ("Kategori (OWASP/CWE/CVE bila ada)", extra_f.cwe_id),
                        ("Aset Terdampak", extra_f.asset_name or effective_asset),
                        ("Jenis Aset", extra_f.asset_type or effective_asset_type),
                        ("Domain/IP", extra_f.domain_ip or effective_domain_ip),
                        ("URL/Endpoint", extra_f.endpoint),
                        ("Versi Aplikasi (jika diketahui)", extra_f.app_version or effective_app_ver),
                        ("Severity", extra_f.severity_label),
                        ("CVSS Score", f"{extra_f.cvss_score:.1f}"),
                        ("Deskripsi Kerentanan", extra_f.description),
                        ("Dampak", extra_f.impact),
                        ("Rekomendasi Perbaikan", extra_f.remediation_summary),
                        ("Referensi", extra_f.references),
                    ]
                    tbl_extra = doc.add_table(rows=len(extra_rows), cols=2)
                    TemplateBuilder.populate_two_col_table(tbl_extra, extra_rows)

                    # Steps to Reproduce
                    h_steps = doc.add_paragraph(style="Heading 3")
                    h_steps.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                    r_steps = h_steps.add_run("Steps to Reproduce")
                    r_steps.font.name = cls.FONT_NAME
                    r_steps.font.size = Pt(12)
                    r_steps.font.bold = True
                    r_steps.font.color.rgb = cls.BLACK

                    steps_text = "\n".join(f"{s_i}. {s_t}" for s_i, s_t in enumerate(extra_f.steps_to_reproduce, 1)) if extra_f.steps_to_reproduce else "Tidak ada langkah reproduksi spesifik."
                    p_steps = doc.add_paragraph()
                    p_steps.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                    r_st = p_steps.add_run(steps_text)
                    r_st.font.name = cls.FONT_NAME
                    r_st.font.size = Pt(12)
                    r_st.font.color.rgb = cls.BLACK

                    # Proof of Concept
                    h_poc = doc.add_paragraph(style="Heading 3")
                    h_poc.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
                    r_poc = h_poc.add_run("Proof of Concept")
                    r_poc.font.name = cls.FONT_NAME
                    r_poc.font.size = Pt(12)
                    r_poc.font.bold = True
                    r_poc.font.color.rgb = cls.BLACK

                    poc_sub_parts = []
                    if extra_f.redacted_request:
                        poc_sub_parts.append("--- Bukti HTTP Request (Tersanitasi) ---\n" + extra_f.redacted_request)
                    if extra_f.redacted_response:
                        poc_sub_parts.append("--- Bukti HTTP Response (Tersanitasi) ---\n" + extra_f.redacted_response)
                    if extra_f.remediation_code:
                        poc_sub_parts.append("--- Rekomendasi Patch Kode (DevFixer Blueprint) ---\n" + extra_f.remediation_code)
                    
                    p_poc = doc.add_paragraph()
                    p_poc.alignment = WD_ALIGN_PARAGRAPH.LEFT
                    r_poc_body = p_poc.add_run("\n\n".join(poc_sub_parts) if poc_sub_parts else "Bukti tersanitasi terlampir.")
                    r_poc_body.font.name = cls.FONT_NAME
                    r_poc_body.font.size = Pt(11)
                    r_poc_body.font.color.rgb = cls.BLACK

        cls.replace_all_placeholders(doc, replacements)
        cls.format_all_tables_monochrome(doc)
        cls.format_all_paragraphs_academic(doc)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        doc.save(str(output_path))
        return output_path