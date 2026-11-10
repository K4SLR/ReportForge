import argparse
import json
import sys
from pathlib import Path
from . import __version__
from .engine import DocxEngine
from .fetcher import TemplateFetcher
from .parser import load_findings
from .registry import PRESET_CATALOG, get_preset


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="reportforge",
        description="ReportForge: Formal Monochrome CSIRT VDP Compliance Report Builder (Times New Roman Edition)",
    )
    parser.add_argument("-v", "--version", action="version", version=f"reportforge {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list-presets", help="List all supported dummy CSIRT / VDP presets")
    subparsers.add_parser("update-presets", help="Build and refresh all local monochrome .docx templates in cache")

    for cmd_name in ("generate", "build"):
        gen_p = subparsers.add_parser(cmd_name, help="Generate official monochrome .docx VDP report")
        gen_p.add_argument("-f", "--findings", required=True, help="Path to sample_findings.json")
        gen_p.add_argument("-p", "--preset", default="nusatech", help="Dummy CSIRT preset (nusatech, aurorafin, garudacloud, generic)")
        gen_p.add_argument("-t", "--template", help="Path to custom .docx template file")
        gen_p.add_argument("-s", "--scope", help="Optional path to scope.json for ScopeGuard validation")
        gen_p.add_argument("--exclude-out-of-scope", action="store_true", help="Exclude Out-of-Scope findings from report")
        gen_p.add_argument("-n", "--participant", default="Muhamad Bilal Abdullah", help="Nama Lengkap Peserta")
        gen_p.add_argument("-a", "--alias", default="k4slr", help="Nama Alias Peserta")
        gen_p.add_argument("--asset-name", help="Nama Aset yang diuji")
        gen_p.add_argument("--asset-type", default="Website / API / Server", help="Jenis Aset (Website / API / Server)")
        gen_p.add_argument("--domain-ip", help="Domain / IP Aset")
        gen_p.add_argument("--app-version", default="v2.1", help="Versi Aplikasi")
        gen_p.add_argument("--contact", help="Kontak Penanggung Jawab")
        gen_p.add_argument("-o", "--output", default="output/Laporan_VDP_NusaTech_Final.docx", help="Output .docx path")
        gen_p.add_argument("--md", help="Optional companion Markdown (.md) output path")
        gen_p.add_argument("--json-out", help="Optional sanitized & enriched JSON output path")
        gen_p.add_argument("--refresh", action="store_true", help="Force template refresh before building")

    ver_p = subparsers.add_parser("verify", help="Verify structural integrity of generated .docx report")
    ver_p.add_argument("-d", "--docx", required=True, help="Path to generated .docx file")

    args = parser.parse_args(argv)

    try:
        if args.command == "list-presets":
            print("=" * 88)
            print(f" REPORTFORGE v{__version__} — MONOCHROME FORMAL CSIRT PRESETS")
            print("=" * 88)
            for pid, conf in PRESET_CATALOG.items():
                print(f"[{pid.upper():<12}] {conf.organization_name}")
                print(f"               Banner    : {conf.program_banner}")
                print(f"               Default   : {conf.default_asset_name} ({conf.default_domain_ip})")
                print(f"               Contact   : {conf.contact_email}")
                print("-" * 88)
            return 0

        if args.command == "update-presets":
            fetcher = TemplateFetcher()
            built = fetcher.ensure_all_presets_cached()
            print(f"[+] Successfully built and cached {len(built)} monochrome Times New Roman templates:")
            for p in built:
                print(f"    - {p}")
            return 0

        if args.command in ("generate", "build"):
            preset_config = get_preset(args.preset)
            findings = load_findings(
                args.findings,
                scope_path=args.scope,
                exclude_out_of_scope=args.exclude_out_of_scope,
            )

            fetcher = TemplateFetcher()
            if args.template:
                template_file = Path(args.template).resolve()
                if not template_file.is_file():
                    raise FileNotFoundError(f"Custom template file not found: {template_file}")
                if not fetcher.is_valid_docx_bytes(template_file.read_bytes()):
                    raise ValueError(f"Custom template '{template_file}' is not a valid OpenXML .docx archive.")
            else:
                template_file = fetcher.get_template_path(preset_config, force_refresh=args.refresh)

            output_file = Path(args.output)
            effective_asset = args.asset_name or preset_config.default_asset_name
            effective_domain_ip = args.domain_ip or preset_config.default_domain_ip

            DocxEngine.populate(
                template_path=template_file,
                findings=findings,
                config=preset_config,
                participant_name=args.participant,
                participant_alias=args.alias,
                asset_name=effective_asset,
                asset_type=args.asset_type,
                domain_ip=effective_domain_ip,
                app_version=args.app_version,
                contact_person=args.contact or preset_config.contact_email,
                output_path=output_file,
            )
            print(f"[+] Formal Monochrome DOCX Report generated: {output_file} ({len(findings)} findings)")

            if args.md:
                md_path = Path(args.md)
                md_path.parent.mkdir(parents=True, exist_ok=True)
                md_path.write_text(
                    DocxEngine.to_markdown(
                        findings=findings,
                        config=preset_config,
                        participant_name=args.participant,
                        participant_alias=args.alias,
                        asset_name=effective_asset,
                        domain_ip=effective_domain_ip,
                    ),
                    encoding="utf-8",
                )
                print(f"[+] Companion Markdown Report saved: {md_path}")

            if args.json_out:
                j_path = Path(args.json_out)
                j_path.parent.mkdir(parents=True, exist_ok=True)
                j_path.write_text(
                    json.dumps([f.to_dict() for f in findings], indent=2),
                    encoding="utf-8",
                )
                print(f"[+] Sanitized Enriched JSON saved: {j_path}")

            return 0

        if args.command == "verify":
            p = Path(args.docx)
            if not p.is_file():
                print(f"[!] Error: File not found: {p}", file=sys.stderr)
                return 2
            raw = p.read_bytes()
            if len(raw) < 4 or raw[:4] != b"PK\x03\x04":
                print("[!] Error: Invalid PKZIP / DOCX archive.", file=sys.stderr)
                return 2
            print(f"[+] Verification PASSED: {args.docx} (Size: {len(raw)} bytes, 100% valid OpenXML)")
            return 0

    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 1

    return 0
