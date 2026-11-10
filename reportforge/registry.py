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
        organization_name="PT Nusantara Siber Dinamika (NusaTech CSIRT)",
        program_banner="NUSATECH VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="nusatech_vdp_template.docx",
        language="id",
        default_asset_name="Portal Layanan Informasi & Telemetri NusaTech",
        default_asset_type="Website / API / Server",
        default_domain_ip="portal.nusatech.local / 192.0.2.10",
        default_app_version="v2.1",
        contact_email="csirt@nusatech.local / 0812-0000-0001",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
    "aurorafin": PresetConfig(
        preset_id="aurorafin",
        organization_name="PT Aurora Finansial Digital (AuroraFin CSIRT)",
        program_banner="AURORAFIN VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="aurorafin_vdp_template.docx",
        language="id",
        default_asset_name="Sistem Gerbang Transaksi & Faktur AuroraFin",
        default_asset_type="Website / API",
        default_domain_ip="api.aurorafin.local / 198.51.100.25",
        default_app_version="v3.4",
        contact_email="security@aurorafin.local / 0812-0000-0002",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
    "garudacloud": PresetConfig(
        preset_id="garudacloud",
        organization_name="PT Garuda Komputasi Awan (GarudaCloud CSIRT)",
        program_banner="GARUDACLOUD VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="garudacloud_vdp_template.docx",
        language="id",
        default_asset_name="Konsol Manajemen Infrastruktur GarudaCloud",
        default_asset_type="Website / API / Server",
        default_domain_ip="console.garudacloud.local / 203.0.113.50",
        default_app_version="v1.8",
        contact_email="vdp@garudacloud.local / 0812-0000-0003",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
    "generic": PresetConfig(
        preset_id="generic",
        organization_name="Organisasi Pengelola Sistem Elektronik (Dummy CSIRT)",
        program_banner="VULNERABILITY DISCLOSURE PROGRAM",
        template_filename="generic_vdp_template.docx",
        language="id",
        default_asset_name="Portal Aplikasi Web Fiktif",
        default_asset_type="Website / API / Server",
        default_domain_ip="aset.organisasi-fiktif.local / 192.0.2.100",
        default_app_version="v1.0",
        contact_email="csirt@organisasi-fiktif.local / 0812-0000-0000",
        download_url=None,
        field_mappings=dict(COMMON_PLACEHOLDERS),
    ),
}


def get_preset(preset_name: str) -> PresetConfig:
    key = preset_name.lower().strip()
    if key not in PRESET_CATALOG:
        valid = ", ".join(sorted(PRESET_CATALOG.keys()))
        raise ValueError(f"Preset '{preset_name}' tidak ditemukan. Pilihan valid: {valid}")
    return PRESET_CATALOG[key]
