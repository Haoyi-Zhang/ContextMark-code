"""Exact owned unittest inventory and result gate for current reproductions."""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import re

EXPECTED_TESTS = 136
EXPECTED_TEST_IDS_SHA256 = "99bb8e337ff6c3d161144c7386e712f331eb1edfe2c4a6efcf048cd52919c8c1"


def source_test_ids(root: Path) -> list[str]:
    ids: list[str] = []
    for path in sorted((root / "tests").glob("test_*.py")):
        module = ast.parse(path.read_text(encoding="utf-8"))
        for group in module.body:
            if isinstance(group, ast.ClassDef):
                for method in group.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)) and method.name.startswith("test_"):
                        ids.append(f"{path.stem}.{group.name}.{method.name}")
    return sorted(ids)


def ids_sha256(ids: list[str]) -> str:
    return hashlib.sha256("\n".join(sorted(ids)).encode("utf-8")).hexdigest()


def source_inventory_valid(root: Path) -> bool:
    ids = source_test_ids(root)
    return len(ids) == EXPECTED_TESTS and ids_sha256(ids) == EXPECTED_TEST_IDS_SHA256


def test_output_valid(output: str, returncode: int, root: Path) -> bool:
    source_ids = source_test_ids(root)
    observed_ids = re.findall(
        r"(?m)^test_[A-Za-z0-9_]+ \((test_[A-Za-z0-9_]+\.[A-Za-z0-9_]+\.test_[A-Za-z0-9_]+)\) \.\.\. ",
        output,
    )
    return (
        returncode == 0
        and len(source_ids) == EXPECTED_TESTS
        and ids_sha256(source_ids) == EXPECTED_TEST_IDS_SHA256
        and len(observed_ids) == EXPECTED_TESTS
        and len(set(observed_ids)) == EXPECTED_TESTS
        and sorted(observed_ids) == source_ids
        and re.search(rf"(?m)^Ran {EXPECTED_TESTS} tests in [0-9.]+s\r?$", output) is not None
        and output.rstrip().endswith("OK")
    )
