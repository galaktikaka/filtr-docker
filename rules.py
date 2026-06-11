"""Правила фильтрации. Расширяйте списки без правок scanner.py."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

# Любое срабатывание -> exit 1
WARNINGS_BLOCK = True

SIZE_WARNING_BYTES = 50 * 1024 * 1024
SIZE_CRITICAL_BYTES = 100 * 1024 * 1024
MAX_TEXT_SCAN_BYTES = 1 * 1024 * 1024

PHP_OPEN_TAG = re.compile(rb"<\?php", re.IGNORECASE)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
ENV_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")

# --- расширения ---
SECRET_EXTENSIONS = {".pem", ".key", ".crt", ".p12", ".jks"}
ARCHIVE_EXTENSIONS = {".zip", ".gz", ".7z", ".bak", ".tgz"}
SUSPICIOUS_TAR_IN_APP = {".tar"}
LOG_EXTENSIONS = {".log"}
TEMP_EXTENSIONS = {".tmp", ".cache"}
PHP_EXTENSIONS = {".php"}
# .pl / .cgi — только в слое приложения
SCRIPT_EXTENSIONS = {".cgi", ".pl"}

BINARY_EXTENSIONS = {
    ".so",
    ".exe",
    ".dll",
    ".dylib",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".woff",
    ".woff2",
    ".ico",
    ".pyc",
    ".pyo",
    ".class",
    ".jar",
    ".deb",
    ".rpm",
}

# --- точные имена файлов ---
SECRET_BASENAMES = {"id_rsa", "id_dsa", "id_ed25519", "id_ecdsa"}
CONFIDENTIAL_BASENAMES = {
    "secrets.json",
    "credentials.json",
    "config.local.yml",
    "config.local.yaml",
}
DEBUG_SCRIPT_BASENAMES = {"test.sh", "debug.sh"}
COMPOSE_BASENAMES = {"docker-compose.yml", "docker-compose.yaml"}
ENV_FILE_BASENAMES = {".env"}
ENV_FILE_SUFFIXES = (".env.local",)
SENSITIVE_ENV_KEYWORDS = (
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "access_key",
    "private_key",
    "client_secret",
    "credentials",
)

# --- сегменты пути (каталоги) ---
FORBIDDEN_DIR_NAMES = {
    ".git",
    ".idea",
    ".vscode",
    "__pycache__",
    ".pytest_cache",
    "tests",
    "logs",
    "backup",
}

APPLICATION_LAYER_PREFIXES = (
    "app/",
    "opt/",
    "srv/",
    "home/",
    "workspace/",
    "src/",
)

# Пути, где сертификаты допустимы
PATH_WHITELIST_PREFIXES = (
    "etc/ssl/",
    "usr/share/ca-certificates/",
    "usr/share/ca/",
)


@dataclass(frozen=True)
class RuleHit:
    rule_type: str
    level: str  # CRITICAL | WARNING
    message: str
    line_no: int | None = None
    snippet: str | None = None


def _normalize_rel(rel_posix: str) -> str:
    return rel_posix.lstrip("./")


def in_application_layer(rel_posix: str) -> bool:
    """Сканируем /app и типичные каталоги приложения"""
    norm = _normalize_rel(rel_posix)
    return any(
        norm == prefix.rstrip("/") or norm.startswith(prefix)
        for prefix in APPLICATION_LAYER_PREFIXES
    )


def _path_has_whitelisted_prefix(rel_posix: str) -> bool:
    norm = _normalize_rel(rel_posix)
    if any(norm.startswith(p) for p in PATH_WHITELIST_PREFIXES):
        return True
    # bundled CA в pip/certifi
    if "site-packages" in norm and "certifi" in norm:
        return True
    return False


def _forbidden_directory_in_path(rel_posix: str) -> str | None:
    """Только каталоги-предки, не имя файл"""
    parts = Path(rel_posix).parts
    for part in parts[:-1]:
        if part in FORBIDDEN_DIR_NAMES:
            return part
    return None


def is_binary_file(path: Path, sample_size: int = 8192) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as fh:
            chunk = fh.read(sample_size)
    except OSError:
        return True
    return b"\x00" in chunk


def _is_env_file(name: str) -> bool:
    lowered = name.lower()
    return lowered in ENV_FILE_BASENAMES or lowered.endswith(ENV_FILE_SUFFIXES)


def _clip_snippet(value: str, max_len: int = 160) -> str:
    compact = " ".join(value.strip().split())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def _is_sensitive_env_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in SENSITIVE_ENV_KEYWORDS)


def _looks_like_placeholder(value: str) -> bool:
    stripped = value.strip().strip("'\"")
    if not stripped:
        return True
    return bool(re.fullmatch(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?", stripped))


def _is_raw_ip_host(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False


def _url_issue(url: str) -> str | None:
    host = urlparse(url).hostname or ""
    lowered = host.lower()
    if not lowered:
        return None
    if lowered in {"localhost", "0.0.0.0"}:
        return "URL uses localhost/0.0.0.0 host"
    if _is_raw_ip_host(lowered):
        return "URL uses raw IP address instead of domain"
    return None


def check_file(path: Path, rel_posix: str) -> list[RuleHit]:
    """Проверка одного файла. rel_posix — путь относительно корня сканирования"""
    if not in_application_layer(rel_posix):
        return []

    hits: list[RuleHit] = []
    name = path.name
    suffix = path.suffix.lower()
    suffixes = "".join(path.suffixes).lower() if path.suffixes else suffix

    forbidden_dir = _forbidden_directory_in_path(rel_posix)
    if forbidden_dir:
        hits.append(
            RuleHit(
                "forbidden_dir",
                "CRITICAL",
                f"forbidden directory segment: {forbidden_dir}/",
            )
        )

    if name in SECRET_BASENAMES:
        hits.append(RuleHit("secret", "CRITICAL", "private key filename"))
    elif suffix in SECRET_EXTENSIONS and not _path_has_whitelisted_prefix(rel_posix):
        hits.append(RuleHit("secret", "CRITICAL", "certificate or key material in image"))

    if name in CONFIDENTIAL_BASENAMES:
        hits.append(RuleHit("secret", "CRITICAL", "secret configuration file"))

    if suffix in ARCHIVE_EXTENSIONS or suffixes.endswith(".tar.gz"):
        hits.append(RuleHit("archive", "WARNING", "archive or backup in image"))
    elif suffix in SUSPICIOUS_TAR_IN_APP:
        hits.append(RuleHit("archive", "WARNING", "tar archive in application layer"))

    if suffix in LOG_EXTENSIONS:
        hits.append(RuleHit("log", "WARNING", "log file in image"))
    if suffix in TEMP_EXTENSIONS:
        hits.append(RuleHit("temp", "WARNING", "temporary or cache file"))

    if name in DEBUG_SCRIPT_BASENAMES:
        hits.append(RuleHit("test_artifact", "WARNING", "test or debug script"))
    if name in COMPOSE_BASENAMES:
        hits.append(RuleHit("compose", "WARNING", "docker-compose file inside image"))

    if suffix in PHP_EXTENSIONS:
        hits.append(RuleHit("php", "CRITICAL", "PHP file not allowed in image"))
    if suffix in SCRIPT_EXTENSIONS:
        hits.append(RuleHit("script", "WARNING", "legacy script file in image"))

    try:
        size = path.stat().st_size
    except OSError:
        return hits

    if size > SIZE_CRITICAL_BYTES:
        hits.append(RuleHit("size", "CRITICAL", f"file larger than {SIZE_CRITICAL_BYTES // (1024*1024)}MB"))
    elif size > SIZE_WARNING_BYTES:
        hits.append(RuleHit("size", "WARNING", f"file larger than {SIZE_WARNING_BYTES // (1024*1024)}MB"))

    if not is_binary_file(path) and size <= MAX_TEXT_SCAN_BYTES:
        hits.extend(_check_text_content(path, is_env_file=_is_env_file(name)))

    return hits


def _check_text_content(path: Path, *, is_env_file: bool) -> list[RuleHit]:
    hits: list[RuleHit] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits

    for idx, raw_line in enumerate(text.splitlines(), start=1):
        lowered = raw_line.lower()
        snippet = _clip_snippet(raw_line)

        if "<?php" in lowered and path.suffix.lower() != ".php":
            hits.append(
                RuleHit(
                    "php",
                    "CRITICAL",
                    "PHP opening tag in non-PHP file",
                    line_no=idx,
                    snippet=snippet,
                )
            )

        for match in URL_RE.finditer(raw_line):
            url = match.group(0)
            issue = _url_issue(url)
            if issue:
                hits.append(
                    RuleHit(
                        "url",
                        "WARNING",
                        issue,
                        line_no=idx,
                        snippet=_clip_snippet(url),
                    )
                )

        if is_env_file:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = ENV_ASSIGNMENT_RE.match(raw_line)
            if not m:
                continue
            key, value = m.group(1), m.group(2)
            if _is_sensitive_env_key(key) and not _looks_like_placeholder(value):
                hits.append(
                    RuleHit(
                        "env_secret",
                        "CRITICAL",
                        f"sensitive env key has literal value: {key}",
                        line_no=idx,
                        snippet=snippet,
                    )
                )
    return hits
