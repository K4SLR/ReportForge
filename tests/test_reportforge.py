import json
import tempfile
import unittest
from pathlib import Path
from reportforge.cli import main
from reportforge.engine import DocxEngine
from reportforge.enrichment import CVSS31Calculator, HTTPSanitizer, clean_xml_string
from reportforge.fetcher import TemplateFetcher
from reportforge.parser import load_findings
from reportforge.registry import get_preset


class TestReportForgeV2Suite(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name)
        self.findings_path = self.base / "sample_findings.json"
        self.scope_path = self.base / "scope.json"

        sample = [
            {
                "id": "TEST-001",
                "title": "Broken Access Control (IDOR) on Telemetry Export",
                "endpoint": "https://portal.nusatech.local/api/v1/dokumen/unduh?id=801",
                "vuln_type": "IDOR",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "description": "Endpoint fails to validate ownership of requested document ID.\x00\x07",
                "impact": "Users can access documents belonging to other users.",
                "status": "OPEN",
                "steps_to_reproduce": ["Step 1", "Step 2"],
                "raw_http_request": "GET /api/v1/dokumen/unduh?id=801&api_key=secret99 HTTP/1.1\r\nHost: portal.nusatech.local\r\nCookie: sid=secret123\r\n\r\n",
            },
            {
                "id": "TEST-002",
                "title": "Out of Scope Legacy Banner",
                "endpoint": "https://legacy-archive.nusatech.local/status",
                "vuln_type": "INFO_DISCLOSURE",
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "description": "Banner disclosure.",
                "impact": "Info.",
                "status": "IGNORED",
                "steps_to_reproduce": ["Send HEAD."],
            }
        ]
        self.findings_path.write_text(json.dumps(sample), encoding="utf-8")
        self.scope_path.write_text(
            json.dumps({"program_name": "NusaTech Test", "in_scope": ["*.nusatech.local"], "out_of_scope": ["legacy-archive.*"]}),
            encoding="utf-8"
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_enrichment_and_redaction(self):
        findings = load_findings(self.findings_path, scope_path=self.scope_path, exclude_out_of_scope=True)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.id, "TEST-001")
        self.assertEqual(f.cvss_score, 6.5)
        self.assertEqual(f.severity_label, "Medium")
        self.assertNotIn("secret99", f.redacted_request)
        self.assertNotIn("secret123", f.redacted_request)
        self.assertIn("[REDACTED]", f.redacted_request)

    def test_generate_monochrome_docx_and_verify(self):
        out_docx = self.base / "Laporan_Uji.docx"
        rc = main([
            "generate",
            "-f", str(self.findings_path),
            "-s", str(self.scope_path),
            "-p", "nusatech",
            "--exclude-out-of-scope",
            "-n", "Muhamad Bilal Abdullah",
            "-a", "k4slr",
            "-o", str(out_docx)
        ])
        self.assertEqual(rc, 0)
        self.assertTrue(out_docx.exists())
        self.assertTrue(out_docx.stat().st_size > 10000)


if __name__ == "__main__":
    unittest.main()
