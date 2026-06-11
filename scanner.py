#!/usr/bin/env python3
"""
Сканер Docker-образов
"""

from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

from report import ScanReport
from rules import check_file

EXIT_OK = 0
EXIT_VIOLATIONS = 1
EXIT_TOOL_ERROR = 2


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Фильтр Docker-образов перед prod")
    parser.add_argument("image", help="IMAGE:TAG (тег по умолчанию — latest)")
    parser.add_argument("--report", type=Path, help="Путь к JSON-отчёту")
    parser.add_argument(
        "--guidance",
        type=Path,
        help="Путь к текстовому файлу с рекомендациями (при FAILED)",
    )
    parser.add_argument(
        "--no-hints",
        action="store_true",
        help="Не выводить рекомендации в консоль при FAILED",
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        help="Каталог для распаковки (иначе CONTAINER_SCAN_WORKDIR или временный)",
    )
    return parser.parse_args(argv)


def normalize_image_ref(image: str) -> str:
    if ":" not in image.split("/")[-1]:
        return f"{image}:latest"
    return image


def container_engine() -> str:
    override = os.environ.get("CONTAINER_ENGINE", "").strip()
    if override:
        return override
    if shutil.which("podman"):
        return "podman"
    return "docker"


def container_save(image: str, archive: Path) -> None:
    engine = container_engine()
    result = subprocess.run(
        [engine, "save", "-o", str(archive), image],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or f"{engine} save failed").strip()
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(EXIT_TOOL_ERROR)


def _extract_tar_members(tf: tarfile.TarFile, dest: Path) -> None:
    for member in tf.getmembers():
        if member.issym() or member.islnk():
            continue
        try:
            tf.extract(member, dest, filter="data")
        except TypeError:
            tf.extract(member, dest)


def safe_extract_tar(tar_path: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r") as tf:
        _extract_tar_members(tf, dest)


def _manifest_layer_paths(unpack_dir: Path) -> list[Path]:
    manifest_path = unpack_dir / "manifest.json"
    if not manifest_path.is_file():
        return []
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    entries = data if isinstance(data, list) else [data]
    paths: list[Path] = []
    for entry in entries:
        for layer in entry.get("Layers", []):
            blob = unpack_dir / layer
            if blob.is_file():
                paths.append(blob)
    return paths


def extract_oci_layers(unpack_dir: Path, merge_dir: Path) -> bool:
    """Слои Docker Desktop"""
    layer_blobs = _manifest_layer_paths(unpack_dir)
    if not layer_blobs:
        return False
    merge_dir.mkdir(parents=True, exist_ok=True)
    for blob in layer_blobs:
        try:
            with gzip.open(blob, "rb") as gz_stream:
                with tarfile.open(fileobj=gz_stream, mode="r|*") as tf:
                    _extract_tar_members(tf, merge_dir)
        except (OSError, tarfile.TarError):
            safe_extract_tar(blob, merge_dir)
    return True


def unpack_docker_save(archive: Path, unpack_dir: Path, merge_dir: Path) -> Path:
    """Распаковка image.tar и layer-*.tar в единое дерево merge_dir"""
    unpack_dir.mkdir(parents=True, exist_ok=True)
    merge_dir.mkdir(parents=True, exist_ok=True)

    safe_extract_tar(archive, unpack_dir)

    if extract_oci_layers(unpack_dir, merge_dir):
        return merge_dir

    layer_tars = sorted(
        p
        for p in unpack_dir.rglob("*.tar")
        if p.resolve() != archive.resolve() and p.name != "image.tar"
    )
    if layer_tars:
        for layer in layer_tars:
            safe_extract_tar(layer, merge_dir)
        return merge_dir

    return unpack_dir


def scan_tree(root: Path, report: ScanReport) -> None:
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        # не заходим в служебные каталоги docker save
        dirnames[:] = [
            d
            for d in dirnames
            if d not in {"repositories", "blobs", "manifest.json"}
            and not d.endswith(".json")
        ]
        for name in filenames:
            if name in {"manifest.json", "repositories"}:
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                continue
            try:
                rel = full.relative_to(root).as_posix()
            except ValueError:
                continue
            if not full.is_file():
                continue
            for hit in check_file(full, rel):
                report.add(
                    f"/{rel}",
                    hit.rule_type,
                    hit.level,
                    hit.message,
                    line_no=hit.line_no,
                    snippet=hit.snippet,
                )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    image = normalize_image_ref(args.image)

    workdir = args.workdir or os.environ.get("CONTAINER_SCAN_WORKDIR")
    owns_workdir = False
    if workdir is None:
        workdir = Path(f"/tmp/container-scan-{os.getpid()}")
        owns_workdir = True
    else:
        workdir = Path(workdir)

    workdir.mkdir(parents=True, exist_ok=True)
    archive = workdir / "image.tar"
    unpack_dir = workdir / "unpack"
    merge_dir = workdir / "filesystem"

    report = ScanReport(image=image)

    try:
        container_save(image, archive)
        scan_root = unpack_docker_save(archive, unpack_dir, merge_dir)
        scan_tree(scan_root, report)
    except (OSError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_TOOL_ERROR
    finally:
        if owns_workdir and workdir.exists():
            shutil.rmtree(workdir, ignore_errors=True)

    report.print_human(show_guidance=not args.no_hints)
    if args.report:
        report.write_json(args.report)
    if args.guidance and not report.passed():
        report.write_guidance(args.guidance)

    return report.exit_code()


if __name__ == "__main__":
    raise SystemExit(main())
