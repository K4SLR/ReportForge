import fnmatch
import json
import math
import posixpath
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

_INVALID_XML_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean_xml_string(text: str) -> str:
    if not text:
        return ""
    return _INVALID_XML_CHARS_RE.sub("", str(text))


class CVSS31Calculator:
    """FIRST.org CVSS v3.1 Base Score Calculator using official CSIRT severity labels."""

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}
    REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

    @staticmethod
    def roundup(val: float) -> float:
        int_input = round(val * 100000)
        if (int_input % 10000) == 0:
            return int_input / 100000.0
        return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def label_for_score(cls, score: float) -> str:
        if score == 0.0:
            return "Informational"
        if score < 4.0:
            return "Low"
        if score < 7.0:
            return "Medium"
        if score < 9.0:
            return "High"
        return "Critical"

    @classmethod
    def normalize_severity_label(cls, raw_label: str, score: float = 0.0) -> str:
        if not raw_label:
            return cls.label_for_score(score)
        up = raw_label.strip().upper()
        mapping = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "WARNING": "Medium",
            "LOW": "Low",
            "INFO": "Informational",
            "INFORMATIONAL": "Informational",
        }
        return mapping.get(up, cls.label_for_score(score))

    @classmethod
    def calculate(cls, vector: str) -> Tuple[float, str]:
        if not vector:
            return 0.0, "Informational"
        clean = vector.strip()
        if clean.upper().startswith("CVSS:3.1/"):
            clean = clean[9:]
        elif clean.upper().startswith("CVSS:3.0/"):
            clean = clean[9:]

        metrics: Dict[str, str] = {}
        for part in clean.split("/"):
            if ":" not in part:
                continue
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

        missing = cls.REQUIRED_METRICS - set(metrics.keys())
        if missing:
            raise ValueError(f"Missing CVSS metrics: {', '.join(sorted(missing))}")

        s = metrics["S"]
        if s not in ("U", "C"):
            raise ValueError(f"Invalid Scope (S) metric: {s}")

        try:
            av = cls.AV_WEIGHTS[metrics["AV"]]
            ac = cls.AC_WEIGHTS[metrics["AC"]]
            pr = cls.PR_CHANGED[metrics["PR"]] if s == "C" else cls.PR_UNCHANGED[metrics["PR"]]
            ui = cls.UI_WEIGHTS[metrics["UI"]]
            c = cls.CIA_WEIGHTS[metrics["C"]]
            i = cls.CIA_WEIGHTS[metrics["I"]]
            a = cls.CIA_WEIGHTS[metrics["A"]]
        except KeyError as exc:
            raise ValueError(f"Invalid CVSS metric value for {exc}") from exc

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if s == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        if impact <= 0:
            return 0.0, "Informational"

        exploitability = 8.22 * av * ac * pr * ui
        if s == "U":
            base_score = cls.roundup(min(impact + exploitability, 10.0))
        else:
            base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        return base_score, cls.label_for_score(base_score)


class HTTPSanitizer:
    """Redacts sensitive credentials, cookies, and tokens from raw HTTP blocks."""

    SENSITIVE_HEADERS = {
        "authorization", "proxy-authorization", "x-api-key", "x-auth-token",
        "x-csrf-token", "x-xsrf-token", "api-key", "client-secret", "x-amz-security-token",
    }
    SENSITIVE_PARAM_NAMES = (
        r"(?:access_token|refresh_token|auth_token|id_token|token|api_key|apikey|"
        r"secret|client_secret|password|passwd|pwd|session_id|sessionid|sid|phpsessid|jwt|key)"
    )
    QUERY_PARAM_RE = re.compile(rf"([?&]{SENSITIVE_PARAM_NAMES}=)([^&\s#]+)", re.IGNORECASE)
    COOKIE_PAIR_RE = re.compile(r"([A-Za-z0-9_\-]*?(?:sess|token|auth|sid|jwt|key|secret|id)[A-Za-z0-9_\-]*?=)([^;\s]+)", re.IGNORECASE)
    BEARER_INLINE_RE = re.compile(r"\b(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE)
    JSON_SECRET_KEY_RE = re.compile(r"(?:token|secret|password|passwd|pwd|api_key|apikey|auth|session|jwt|private_key|access_key|credential)", re.IGNORECASE)

    @classmethod
    def _redact_json_recursive(cls, obj: Any) -> Any:
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if cls.JSON_SECRET_KEY_RE.search(str(k)) and isinstance(v, (str, int, float)):
                    out[k] = "[REDACTED]"
                else:
                    out[k] = cls._redact_json_recursive(v)
            return out
        if isinstance(obj, list):
            return [cls._redact_json_recursive(item) for item in obj]
        return obj

    @classmethod
    def sanitize_http_block(cls, raw_http: str) -> str:
        if not raw_http or not raw_http.strip():
            return ""

        normalized = clean_xml_string(raw_http).replace("\r\n", "\n")
        if "\n\n" in normalized:
            header_part, body_part = normalized.split("\n\n", 1)
        else:
            header_part, body_part = normalized, ""

        header_lines = header_part.split("\n")
        sanitized_headers: List[str] = []

        for idx, line in enumerate(header_lines):
            if idx == 0:
                sanitized_headers.append(cls.QUERY_PARAM_RE.sub(r"\1[REDACTED]", line))
                continue

            if ":" in line:
                h_name, h_val = line.split(":", 1)
                h_lower = h_name.strip().lower()

                if h_lower in cls.SENSITIVE_HEADERS:
                    val_strip = h_val.strip()
                    if val_strip.lower().startswith("bearer "):
                        sanitized_headers.append(f"{h_name}: Bearer [REDACTED]")
                    elif val_strip.lower().startswith("basic "):
                        sanitized_headers.append(f"{h_name}: Basic [REDACTED]")
                    else:
                        sanitized_headers.append(f"{h_name}: [REDACTED]")
                    continue

                if h_lower in ("cookie", "set-cookie"):
                    redacted_cookie = cls.COOKIE_PAIR_RE.sub(r"\1[REDACTED]", h_val)
                    if redacted_cookie == h_val and "=" in h_val:
                        first_eq = h_val.find("=")
                        semi = h_val.find(";", first_eq)
                        if semi != -1:
                            redacted_cookie = h_val[: first_eq + 1] + "[REDACTED]" + h_val[semi:]
                        else:
                            redacted_cookie = h_val[: first_eq + 1] + "[REDACTED]"
                    sanitized_headers.append(f"{h_name}:{redacted_cookie}")
                    continue

            line = cls.BEARER_INLINE_RE.sub(r"\1[REDACTED]", line)
            line = cls.QUERY_PARAM_RE.sub(r"\1[REDACTED]", line)
            sanitized_headers.append(line)

        sanitized_body = body_part.strip()
        if sanitized_body:
            if (sanitized_body.startswith("{") and sanitized_body.endswith("}")) or (
                sanitized_body.startswith("[") and sanitized_body.endswith("]")
            ):
                try:
                    parsed_json = json.loads(sanitized_body)
                    redacted_json = cls._redact_json_recursive(parsed_json)
                    sanitized_body = json.dumps(redacted_json)
                except Exception:
                    sanitized_body = cls.BEARER_INLINE_RE.sub(r"\1[REDACTED]", sanitized_body)
            else:
                sanitized_body = cls.QUERY_PARAM_RE.sub(r"\1[REDACTED]", "?" + sanitized_body)[1:]
                sanitized_body = cls.BEARER_INLINE_RE.sub(r"\1[REDACTED]", sanitized_body)

        if sanitized_body:
            return "\n".join(sanitized_headers) + "\n\n" + sanitized_body
        return "\n".join(sanitized_headers)


class ScopeGuard:
    def __init__(self, in_scope: List[str], out_of_scope: List[str]):
        self.in_scope = in_scope or ["*"]
        self.out_of_scope = out_of_scope or []

    @staticmethod
    def extract_hostname_and_path(target: str) -> Tuple[str, str, str]:
        target = target.strip()
        if "://" not in target:
            target = "https://" + target
        parsed = urlparse(target)
        host = (parsed.hostname or "").lower()
        netloc = (parsed.netloc or "").lower()
        raw_path = parsed.path or "/"
        norm_path = posixpath.normpath(raw_path)
        if not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        return host, f"{host}{norm_path}", f"{netloc}{norm_path}"

    @classmethod
    def matches_pattern(cls, host: str, host_path: str, netloc_path: str, pattern: str) -> bool:
        pattern = pattern.lower().strip()
        if "://" in pattern:
            p = urlparse(pattern)
            pattern = f"{(p.netloc or p.hostname or '').lower()}{p.path or ''}".rstrip("/")

        clean_pat = pattern.rstrip("/")
        if "/" in pattern:
            clean_hp = host_path.rstrip("/")
            clean_np = netloc_path.rstrip("/")
            for target_path in (clean_hp, clean_np):
                if fnmatch.fnmatch(target_path, clean_pat):
                    return True
                if fnmatch.fnmatch(target_path, clean_pat + "/*"):
                    return True
                if "*" not in clean_pat and target_path.startswith(clean_pat + "/"):
                    return True
            return False

        if ":" in clean_pat:
            netloc_only = netloc_path.split("/", 1)[0]
            if clean_pat.startswith("*."):
                base_netloc = clean_pat[2:]
                return netloc_only == base_netloc or netloc_only.endswith("." + base_netloc)
            return fnmatch.fnmatch(netloc_only, clean_pat)

        if clean_pat.startswith("*."):
            base_domain = clean_pat[2:]
            return host == base_domain or host.endswith("." + base_domain)
        return fnmatch.fnmatch(host, clean_pat)

    def validate(self, target: str) -> Tuple[bool, str]:
        host, host_path, netloc_path = self.extract_hostname_and_path(target)
        if not host:
            return False, "Invalid target hostname"
        for oos in self.out_of_scope:
            if self.matches_pattern(host, host_path, netloc_path, oos):
                return False, f"BLOCKED: Matches Out-of-Scope rule '{oos}'"
        for ins in self.in_scope:
            if self.matches_pattern(host, host_path, netloc_path, ins):
                return True, f"ALLOWED: Matches In-Scope rule '{ins}'"
        return False, "BLOCKED: Target does not match any In-Scope rule"


class RemediationLibrary:
    BLUEPRINTS: Dict[str, Dict[str, str]] = {
        "SQLI": {
            "cwe_id": "CWE-89 / OWASP A03:2021 - Injection",
            "lang": "python",
            "summary": "Gunakan Parameterized Queries (Prepared Statements) pada seluruh kueri basis data serta terapkan validasi daftar putih (allowlist) yang ketat pada parameter pengurutan atau filter kolom.",
            "references": "OWASP Top 10 A03:2021 (Injection), MITRE CWE-89, NIST SP 800-53 SI-10.",
            "code": (
                "ALLOWED_SORT_COLUMNS = {'id', 'created_at', 'station_code'}\n"
                "sort_col = request.args.get('sort', 'id')\n"
                "if sort_col not in ALLOWED_SORT_COLUMNS:\n"
                "    abort(400, 'Parameter pengurutan tidak valid')\n"
                "cursor.execute(f'SELECT id, metric FROM observations WHERE org_id = %s ORDER BY {sort_col} DESC', (current_user.org_id,))"
            ),
        },
        "IDOR": {
            "cwe_id": "CWE-639 / OWASP A01:2021 - Broken Access Control",
            "lang": "python",
            "summary": "Terapkan verifikasi kepemilikan objek (Object-Level Authorization) pada setiap fungsi pengaksesan dokumen dengan memvalidasi kecocokan ID pemilik sumber daya terhadap sesi pengguna yang terautentikasi.",
            "references": "OWASP Top 10 A01:2021 (Broken Access Control), OWASP API Security API1:2023 (BOLA), MITRE CWE-639.",
            "code": (
                "document_record = db.session.execute(\n"
                "    select(Document).where(Document.id == doc_id, Document.owner_id == current_user.id)\n"
                ").scalar_one_or_none()\n"
                "if document_record is None:\n"
                "    abort(403, 'Akses ditolak: Anda tidak memiliki otorisasi atas dokumen ini')"
            ),
        },
        "XSS": {
            "cwe_id": "CWE-79 / OWASP A03:2021 - Cross-Site Scripting (XSS)",
            "lang": "javascript",
            "summary": "Lakukan kontekstual HTML entity encoding pada seluruh input pengguna sebelum dirender ke halaman peramban, hindari penggunaan innerHTML mentah, dan terapkan header Content-Security-Policy (CSP).",
            "references": "OWASP Top 10 A03:2021 (Injection / XSS), MITRE CWE-79, OWASP XSS Prevention Cheat Sheet.",
            "code": (
                "const safeCommentNode = document.createElement('div');\n"
                "safeCommentNode.textContent = untrustedUserInput;\n"
                "threadContainer.appendChild(safeCommentNode);"
            ),
        },
        "SSRF": {
            "cwe_id": "CWE-918 / OWASP A10:2021 - Server-Side Request Forgery",
            "lang": "python",
            "summary": "Validasi skema dan domain tujuan terhadap daftar putih (allowlist) eksplisit serta blokir seluruh akses ke rentang alamat IP privat, loopback, dan link-local metadata setelah resolusi DNS.",
            "references": "OWASP Top 10 A10:2021 (SSRF), MITRE CWE-918, CISA Cloud Security Technical Reference.",
            "code": (
                "resolved_ip = ipaddress.ip_address(socket.gethostbyname(parsed_url.hostname))\n"
                "if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local:\n"
                "    raise ValueError('Akses ke alamat jaringan internal ditolak')"
            ),
        },
        "PATH_TRAVERSAL": {
            "cwe_id": "CWE-22 / OWASP A01:2021 - Path Traversal",
            "lang": "python",
            "summary": "Lakukan kanonikalisasi jalur berkas menggunakan Path.resolve() dan pastikan jalur akhir tetap berada di dalam direktori dasar yang diizinkan menggunakan is_relative_to().",
            "references": "OWASP Top 10 A01:2021 (Broken Access Control), MITRE CWE-22, OWASP File System Security.",
            "code": (
                "safe_base = Path('/var/app/uploads').resolve()\n"
                "target_path = (safe_base / Path(user_filename).name).resolve()\n"
                "if not target_path.is_relative_to(safe_base):\n"
                "    abort(403, 'Percobaan manipulasi direktori diblokir')"
            ),
        },
        "INFO_DISCLOSURE": {
            "cwe_id": "CWE-200 / OWASP A05:2021 - Security Misconfiguration",
            "lang": "nginx",
            "summary": "Nonaktifkan eksposur banner versi perangkat lunak server, batasi akses ke berkas konfigurasi sensitif, dan terapkan penyaringan skema DTO pada respons API publik.",
            "references": "OWASP Top 10 A05:2021 (Security Misconfiguration), MITRE CWE-200, CIS Benchmark Web Server Hardening.",
            "code": (
                "server_tokens off;\n"
                "proxy_hide_header X-Powered-By;\n"
                "location ~ /\.(env|git|svn) { deny all; return 404; }"
            ),
        },
    }

    DEFAULT_BLUEPRINT = {
        "cwe_id": "CWE-284 / OWASP A01:2021 - Improper Access Control",
        "lang": "text",
        "summary": "Terapkan validasi input sisi server, pengodean output, prinsip hak akses minimum (least privilege), serta mekanisme pertahanan berlapis pada titik akhir terdampak.",
        "references": "OWASP Application Security Verification Standard (ASVS v4.0), MITRE CWE-284.",
        "code": "# Pastikan validasi otorisasi dan sanitasi parameter dilakukan secara ketat di sisi server.",
    }

    @classmethod
    def enrich(cls, vuln_type: str) -> Dict[str, str]:
        key = (vuln_type or "").upper().strip()
        if key in ("LFI", "RFI", "TRAVERSAL"):
            key = "PATH_TRAVERSAL"
        elif key in ("BAC", "BOLA"):
            key = "IDOR"
        return cls.BLUEPRINTS.get(key, cls.DEFAULT_BLUEPRINT)
