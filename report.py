"""Формирование отчёта сканирования."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from guidance import build_remediation, format_remediation_text
from rules import WARNINGS_BLOCK


@dataclass
class Finding:
    path: str
    rule_type: str
    level: str
    message: str
    line_no: int | None = None
    snippet: str | None = None


@dataclass
class ScanReport:
    image: str
    findings: list[Finding] = field(default_factory=list)

    def add(
        self,
        path: str,
        rule_type: str,
        level: str,
        message: str,
        *,
        line_no: int | None = None,
        snippet: str | None = None,
    ) -> None:
        self.findings.append(
            Finding(path, rule_type, level, message, line_no=line_no, snippet=snippet)
        )

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.level == "CRITICAL")

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.level == "WARNING")

    def passed(self) -> bool:
        if self.critical_count:
            return False
        if self.warning_count and WARNINGS_BLOCK:
            return False
        return True

    def exit_code(self) -> int:
        return 0 if self.passed() else 1

    def print_human(self, *, show_guidance: bool = True) -> None:
        for f in sorted(self.findings, key=lambda x: (x.level != "CRITICAL", x.path)):
            where = f"{f.path}:{f.line_no}" if f.line_no is not None else f.path
            details = f" | {f.snippet}" if f.snippet else ""
            print(f"[{f.level}] {where} — {f.message}{details}")
        status = "ПРОЙДЕН" if self.passed() else "ОТКЛОНЕН"
        print(
            f"\nРезультат проверки: {status} "
            f"({self.critical_count} критичных, {self.warning_count} предупреждений)"
        )
        print(f"Образ: {self.image}")
        print("Область проверки: слой приложения (/app, /opt, /srv, /home, /workspace, /src)")
        if show_guidance and not self.passed():
            print(format_remediation_text(self.findings, self.image))

    def write_json(self, path: Path, *, include_guidance: bool = True) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "image": self.image,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "passed": self.passed(),
            "exit_code": self.exit_code(),
            "critical_count": self.critical_count,
            "warning_count": self.warning_count,
            "findings": [asdict(f) for f in self.findings],
        }
        if include_guidance and not self.passed():
            payload["remediation"] = build_remediation(self.findings)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def write_guidance(self, path: Path) -> None:
        """Текстовый отчёт с рекомендациями"""
        path.parent.mkdir(parents=True, exist_ok=True)
        body = format_remediation_text(self.findings, self.image)
        path.write_text(body + "\n", encoding="utf-8")
