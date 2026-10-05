#!/usr/bin/env python3
"""Read-only verifier for either the full TDSC-01 package or artifact root.

Examples
--------
Full scientific package, from its project root::

    python artifact/verify_release.py --root .

Standalone artifact repository, from the artifact root::

    python verify_release.py --root .

The verifier reads the selected package and checks retained execution inputs,
citations, available PDFs, and the optional test suite. It does not fix authors,
page counts, or the current manuscript's bytes to a historical delivery.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any

DEFAULT_PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_TESTS = 89


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def records(root: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        require(not path.is_symlink(), f"symbolic link: {path.relative_to(root)}")
        if path.is_file():
            info = path.stat()
            rows.append({
                "path": path.relative_to(root).as_posix(),
                "bytes": info.st_size,
                "mode": f"{stat.S_IMODE(info.st_mode):04o}",
                "modified_ns": info.st_mtime_ns,
            })
    return rows


def classify_root(root: Path) -> tuple[str, Path, Path | None]:
    """Return mode, artifact root, and optional project root."""
    if (root / "artifact/contextmark").is_dir() and (root / "paper").is_dir():
        return "full_scientific_package", root / "artifact", root
    if (root / "contextmark").is_dir() and (root / "tests").is_dir() and (root / "results").is_dir():
        return "standalone_artifact", root, None
    raise RuntimeError(
        "--root must name either a full TDSC-01 project root or the standalone artifact root"
    )


def verify_execution_manifest(artifact_root: Path) -> dict[str, Any]:
    path = artifact_root / "results/raw/run-manifest.json"
    require(path.is_file(), "missing execution run manifest")
    execution = json.loads(path.read_text(encoding="utf-8"))
    for row in execution["entries"]:
        target = (artifact_root / row["path"]).resolve()
        require(target.is_relative_to(artifact_root.resolve()), "execution path escape")
        require(target.is_file(), f"missing execution evidence: {row['path']}")
        require(sha(target) == row["sha256"], f"execution evidence changed: {row['path']}")
    return execution


def verify_full_package(project_root: Path) -> dict[str, Any]:
    require(
        sorted(path.name for path in project_root.iterdir())
        == ["README.md", "artifact", "paper"],
        "unexpected project-root entries",
    )
    paper = (project_root / "paper/main.tex").read_text(encoding="utf-8")
    commands = [key.strip() for group in re.findall(r"\\cite\{([^}]+)\}", paper)
                for key in group.split(",")]
    bib = re.findall(
        r"(?m)^@\w+\{([^,]+),",
        (project_root / "paper/references.bib").read_text(encoding="utf-8"),
    )
    require(set(commands) == set(bib), "citation keys and bibliography differ")
    reviewed = list(
        csv.DictReader((project_root / "artifact/literature/reference-verification.csv").open())
    )
    require(
        len(reviewed) == len(bib) and {row["citation_key"] for row in reviewed} == set(commands),
        "reference review ledger mismatch",
    )
    support = list(csv.DictReader((project_root / "artifact/citation_support.csv").open()))
    require(
        {row["citation_key"] for row in support} == set(commands),
        "local citation support keys mismatch",
    )
    require("\\bibliographystyle{IEEEtran}" in paper, "not citation-order IEEE bibliography style")

    pdf_check = "unavailable: install PyMuPDF for PDF parse checks"
    try:
        import fitz
        page_counts = {}
        for filename in ("main", "supplement"):
            with fitz.open(project_root / "paper" / f"{filename}.pdf") as document:
                require(len(document) > 0, f"empty PDF: {filename}")
                page_counts[filename] = len(document)
                for page in document:
                    page.get_text("text")
        pdf_check = page_counts
    except ImportError:
        pass
    return {
        "covered_files": len(records(project_root)),
        "references": len(bib),
        "pdf": pdf_check,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_PROJECT_ROOT)
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    root = args.root.expanduser().resolve()
    require(root.is_dir(), f"root is not a directory: {root}")
    mode, artifact_root, project_root = classify_root(root)
    before = records(root)
    execution = verify_execution_manifest(artifact_root)
    full = verify_full_package(project_root) if project_root is not None else None

    test_result = "skipped by explicit flag"
    if not args.skip_tests:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=".")
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"],
            cwd=artifact_root,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
        )
        output = proc.stdout + proc.stderr
        require(
            proc.returncode == 0
            and re.search(rf"Ran {EXPECTED_TESTS} tests", output) is not None
            and "OK" in output,
            output,
        )
        test_result = f"{EXPECTED_TESTS}/{EXPECTED_TESTS} PASS"
    require(before == records(root), "verification modified the selected root")
    require(not list(root.rglob("__pycache__")), "bytecode cache in selected root")

    print(json.dumps({
        "status": "package_checks_completed",
        "mode": mode,
        "root": str(root),
        "execution_files": len(execution["entries"]),
        "release_files": full["covered_files"] if full else None,
        "references": full["references"] if full else "not applicable to standalone artifact",
        "pdf": full["pdf"] if full else "not applicable to standalone artifact",
        "tests": test_result,
        "tree_unchanged": True,
        "external_baseline": "not executed; see local_execution_gaps.json",
    }, indent=2))


if __name__ == "__main__":
    main()
