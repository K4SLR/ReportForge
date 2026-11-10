import io
import ipaddress
import socket
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from .registry import PRESET_CATALOG, PresetConfig
from .template_builder import TemplateBuilder


class TemplateFetcher:
    CACHE_DIR = Path.home() / ".cache" / "reportforge" / "templates"
    MAX_DOWNLOAD_SIZE = 15 * 1024 * 1024

    def __init__(self, cache_dir=None):
        self.cache_dir = (cache_dir or self.CACHE_DIR).resolve()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.builtin_dir = (Path(__file__).resolve().parent.parent / "templates").resolve()
        self.builtin_dir.mkdir(parents=True, exist_ok=True)

    def _safe_cache_path(self, filename):
        clean_name = Path(filename).name
        if not clean_name.endswith(".docx"):
            clean_name += ".docx"
        target = (self.cache_dir / clean_name).resolve()
        if not target.is_relative_to(self.cache_dir):
            raise ValueError(f"Path traversal blocked for template filename: {filename}")
        return target

    @staticmethod
    def validate_remote_url(url):
        parsed = urlparse(url.strip())
        if parsed.scheme.lower() != "https":
            raise ValueError(f"Only HTTPS template URLs are permitted (got '{parsed.scheme}').")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid remote template URL hostname.")

        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
        for item in addr_info:
            ip_str = item[4][0]
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                raise ValueError(f"SSRF Protection: Blocked non-public IP address {ip_str} for {hostname}")

    @staticmethod
    def is_valid_docx_bytes(raw_bytes):
        if not raw_bytes or len(raw_bytes) < 4 or raw_bytes[:4] != b"PK\x03\x04":
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(raw_bytes), "r") as zf:
                names = set(zf.namelist())
                for name in names:
                    if ".." in name or name.startswith("/") or name.startswith("\\"):
                        return False
                return "[Content_Types].xml" in names and "word/document.xml" in names
        except Exception:
            return False

    def ensure_all_presets_cached(self):
        TemplateBuilder.build_all_templates(self.builtin_dir)
        cached_files = []
        for preset_id, cfg in PRESET_CATALOG.items():
            path = self._safe_cache_path(cfg.template_filename)
            TemplateBuilder.build_preset_template(cfg, path)
            cached_files.append(path)
        return cached_files

    def get_template_path(self, config, force_refresh=False):
        target_path = self._safe_cache_path(config.template_filename)

        if target_path.exists() and not force_refresh:
            raw = target_path.read_bytes()
            if self.is_valid_docx_bytes(raw):
                return target_path

        local_builtin = (self.builtin_dir / Path(config.template_filename).name).resolve()
        if not local_builtin.exists() or not self.is_valid_docx_bytes(local_builtin.read_bytes()):
            TemplateBuilder.build_preset_template(config, local_builtin)

        target_path.write_bytes(local_builtin.read_bytes())
        return target_path
