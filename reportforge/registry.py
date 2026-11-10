from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class PresetConfig:
    preset_id: str
    organization_name: str
    program_banner: str
    template_filename: str
    language: str
    default_asset_name: str
    default_asset_type: str
    default_domain_ip: str
    default_app_version: str
    contact_email: str
    download_url: Optional[str] = None
    field_mappings: Dict[str, str] = field(default_factory=dict)


COMMON_PLACEHOLDERS: Dict[str, str] = {
    "report_title": "{{REPORT_TITLE}}",
    "asset_header": "{{ASSET_HEADER}}",
    "program_banner": "{{PROGRAM_BANNER}}",
    "report_date_long": "{{REPORT_DATE_LONG}}",
    "participant_name": "{{NAMA_PESERTA}}",
    "participant_alias": "{{NAMA_ALIAS}}",
    "test_date": "{{TANGGAL_PENGUJIAN}}",
    "asset_name": "{{NAMA_ASET}}",
    "asset_type": "{{JENIS_ASET}}",
    "domain_ip": "{{DOMAIN_IP}}",
    "app_version": "{{VERSI_APLIKASI}}",
    "contact_person": "{{KONTAK_PJ}}",
    "org_name": "{{ORG_NAME}}",
    "vuln_title": "{{JUDUL_KERENTANAN}}",
    "vuln_category": "{{KATEGORI_KERENTANAN}}",
    "endpoint": "{{URL_ENDPOINT}}",
    "severity": "{{SEVERITY}}",
    "cvss_score": "{{CVSS_SCORE}}",
    "description": "{{DESKRIPSI_KERENTANAN}}",
    "impact": "{{DAMPAK_KERENTANAN}}",
    "remediation": "{{REKOMENDASI_PERBAIKAN}}",
    "references": "{{REFERENSI}}",
}


PRESET_CATALOG: Dict[str, PresetConfig] = {
    "nusatech": PresetConfig(
        preset_id="nusatech",
        organization_name="NusaTech Cyber Defense (NusaTech CSIRT)",
        program_banner="NUSATECH VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="nusatech_vdp_template.docx",
        language="en",
        default_asset_name="NusaTech Telemetry & Information Service Portal",
        default_asset_type="Website / API / Server",
        default_domain_ip="portal.nusatech.local / 192.0.2.10",
        default_app_version="v2.1",
        contact_email="csirt@nusatech.local / +1-555-0101",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
    "aurorafin": PresetConfig(
        preset_id="aurorafin",
        organization_name="Aurora Digital Financial Corp (AuroraFin CSIRT)",
        program_banner="AURORAFIN VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="aurorafin_vdp_template.docx",
        language="en",
        default_asset_name="AuroraFin Payment & Settlement Gateway",
        default_asset_type="Website / API",
        default_domain_ip="api.aurorafin.local / 198.51.100.25",
        default_app_version="v3.4",
        contact_email="security@aurorafin.local / +1-555-0102",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
    "garudacloud": PresetConfig(
        preset_id="garudacloud",
        organization_name="Garuda Cloud Systems Inc (GarudaCloud CSIRT)",
        program_banner="GARUDACLOUD VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="garudacloud_vdp_template.docx",
        language="en",
        default_asset_name="GarudaCloud Infrastructure Management Console",
        default_asset_type="Website / API / Server",
        default_domain_ip="console.garudacloud.local / 203.0.113.50",
        default_app_version="v1.8",
        contact_email="vdp@garudacloud.local / +1-555-0103",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
    "generic": PresetConfig(
        preset_id="generic",
        organization_name="Dummy Enterprise Security Response Team (Dummy CSIRT)",
        program_banner="VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="generic_vdp_template.docx",
        language="en",
        default_asset_name="Dummy Enterprise Web Application Portal",
        default_asset_type="Website / API / Server",
        default_domain_ip="asset.dummy-enterprise.local / 192.0.2.100",
        default_app_version="v1.0",
        contact_email="csirt@dummy-enterprise.local / +1-555-0100",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
}


def get_preset(preset_name: str) -> PresetConfig:
    key = preset_name.lower().strip()
    if key not in PRESET_CATALOG:
        valid = ", ".join(sorted(PRESET_CATALOG.keys()))
        raise ValueError(f"Unknown preset '{preset_name}'. Available presets: {valid}")
    return PRESET_CATALOG[key]