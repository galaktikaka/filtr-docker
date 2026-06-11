"""Рекомендации при отклонении образа: ссылки, дежурные фразы, советы по Dockerfile."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from report import Finding

# --- общие ссылки ---
COMMON_LINKS: list[tuple[str, str]] = [
    ("Рекомендации по Dockerfile", "https://docs.docker.com/build/building/best-practices/"),
    ("Многоэтапные сборки", "https://docs.docker.com/build/building/multi-stage/"),
    ("Секреты в Docker Build", "https://docs.docker.com/build/building/secrets/"),
    ("Файл .dockerignore", "https://docs.docker.com/reference/dockerfile/#dockerignore-file"),
    ("Hadolint — линтер Dockerfile", "https://github.com/hadolint/hadolint"),
]

# --- дежурные фразы ---
DUTY_PHRASES = [
    "Образ отклонён фильтром перед репликацией в production. Пуш/деплой заблокирован.",
    "Исправьте Dockerfile и контекст сборки, пересоберите образ и повторите сканирование.",
    "Секреты, сертификаты и тестовые артефакты не должны попадать в итоговый слой образа.",
]

RULE_GUIDANCE: dict[str, dict[str, object]] = {
    "secret": {
        "title": "Секреты и конфиденциальные файлы",
        "tips": [
            "Не используйте COPY для ключей (`.pem`, `.key`), `id_rsa`, `credentials.json`.",
            "Секреты передавайте через orchestrator (Kubernetes Secrets, Vault, CI variables).",
            "Добавьте в `.dockerignore`: `*.pem`, `*.key`, `secrets/`.",
        ],
        "links": [
            ("Secrets в Docker Build", "https://docs.docker.com/build/building/secrets/"),
        ],
    },
    "env_secret": {
        "title": "Секреты в .env",
        "tips": [
            "В `.env` разрешены обычные переменные, но ключи вроде PASSWORD/TOKEN/SECRET не должны иметь literal-значения.",
            "Для чувствительных значений используйте placeholder (`${VAR}`) и подстановку через CI/Kubernetes/Vault.",
        ],
        "links": [
            ("Secrets в Docker Build", "https://docs.docker.com/build/building/secrets/"),
        ],
    },
    "php": {
        "title": "PHP и посторонние скрипты",
        "tips": [
            "Не включайте `.php` и `<?php` в образ, если runtime — Python/Node/Go и т.д.",
            "Веб-стек с PHP — отдельный базовый образ (например `php:fpm`), не «всё в одном».",
        ],
        "links": [
            ("Выбор базового образа", "https://docs.docker.com/build/building/base-images/"),
        ],
    },
    "log": {
        "title": "Логи в образе",
        "tips": [
            "Логи пишите в stdout/stderr контейнера, не в файлы внутри образа.",
            "Исключите `*.log` и каталог `logs/` через `.dockerignore`.",
        ],
        "links": [],
    },
    "archive": {
        "title": "Архивы и backup",
        "tips": [
            "Не копируйте `.zip`, `.bak`, дампы БД в образ — храните в object storage.",
            "Для артефактов сборки используйте multi-stage: в финальный stage — только бинарь/код.",
        ],
        "links": [
            ("Multi-stage builds", "https://docs.docker.com/build/building/multi-stage/"),
        ],
    },
    "test_artifact": {
        "title": "Тесты и отладка",
        "tips": [
            "Каталоги `tests/`, скрипты `test.sh`, `debug.sh` не должны попадать в production-образ.",
            "Тесты запускайте в CI на этапе build, до формирования release-образа.",
        ],
        "links": [],
    },
    "forbidden_dir": {
        "title": "Запрещённые каталоги",
        "tips": [
            "Не копируйте `.git/`, `.idea/`, `__pycache__/`, `tests/` в образ.",
            "Проверьте `.dockerignore` перед `docker build`.",
        ],
        "links": [
            (".dockerignore", "https://docs.docker.com/reference/dockerfile/#dockerignore-file"),
        ],
    },
    "compose": {
        "title": "Docker Compose в образе",
        "tips": [
            "`docker-compose.yml` нужен для локальной разработки, не для prod-образа приложения.",
        ],
        "links": [],
    },
    "temp": {
        "title": "Временные и cache-файлы",
        "tips": [
            "Не включайте `*.tmp`, `*.cache` приложения; используйте volume или tmpfs в runtime.",
        ],
        "links": [],
    },
    "script": {
        "title": "Устаревшие скрипты",
        "tips": [
            "Файлы `.cgi`, `.pl` в слое приложения — признак лишнего; оставьте только нужный runtime.",
        ],
        "links": [],
    },
    "size": {
        "title": "Слишком большие файлы",
        "tips": [
            "Уменьшите образ: slim/alpine база, multi-stage, не копируйте данные в /app.",
        ],
        "links": [
            ("Best practices", "https://docs.docker.com/build/building/best-practices/"),
        ],
    },
    "url": {
        "title": "Подозрительные URL",
        "tips": [
            "Не храните в коде URL с raw IP/localhost; используйте DNS-имена и конфигурацию окружения.",
            "Проверьте, что ссылки не указывают на тестовые/временные адреса.",
        ],
        "links": [],
    },
}

def collect_rule_types(findings: list[Finding]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for f in findings:
        if f.rule_type not in seen:
            seen.add(f.rule_type)
            ordered.append(f.rule_type)
    return ordered


def build_remediation(findings: list[Finding]) -> dict[str, object]:
    """Структура для JSON-отчёта и печати."""
    rule_types = collect_rule_types(findings)
    sections = []
    for rt in rule_types:
        g = RULE_GUIDANCE.get(rt)
        if g:
            sections.append({"rule_type": rt, **g})
    return {
        "duty_phrases": DUTY_PHRASES,
        "common_links": [{"title": t, "url": u} for t, u in COMMON_LINKS],
        "sections": sections,
    }


def format_remediation_text(findings: list[Finding], image: str) -> str:
    """Текстовый блок рекомендаций для stdout."""
    lines: list[str] = []
    sep = "=" * 72

    lines.append("")
    lines.append(sep)
    lines.append("РЕКОМЕНДАЦИИ: как правильно собрать Docker-образ для production")
    lines.append(sep)
    lines.append(f"Образ: {image}")
    lines.append("")

    lines.append("--- Сообщение для разработчика / CI ---")
    for phrase in DUTY_PHRASES:
        lines.append(f"• {phrase}")
    lines.append("")

    rule_types = collect_rule_types(findings)
    if rule_types:
        lines.append("--- По найденным нарушениям ---")
        for rt in rule_types:
            g = RULE_GUIDANCE.get(rt)
            if not g:
                continue
            lines.append("")
            lines.append(f"▸ {g['title']} ({rt})")
            for tip in g.get("tips", []):
                lines.append(f"  — {tip}")
            for title, url in g.get("links", []):
                lines.append(f"  → {title}: {url}")
        lines.append("")

    lines.append("--- Полезные материалы ---")
    for title, url in COMMON_LINKS:
        lines.append(f"• {title}: {url}")
    lines.append("")
    lines.append(sep)

    return "\n".join(lines)
