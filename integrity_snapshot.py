"""
Создаёт снимок всех функций, классов и API-эндпоинтов проекта.
Запускать после каждой рабочей сессии:
    python3 integrity_snapshot.py
"""
import ast
import json
import re
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).parent
SNAPSHOT_FILE = ROOT / "integrity_manifest.json"

SCAN_DIRS = [
    ROOT / "core" / "app",
    ROOT / "workers" / "tasks",
]

SKIP_DIRS = {"__pycache__", ".git", "migrations", "alembic"}


def extract_symbols(path: Path) -> dict:
    src = path.read_text(encoding="utf-8", errors="ignore")
    rel = str(path.relative_to(ROOT))

    functions, classes, routes = [], [], []

    try:
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                if not node.name.startswith("_"):
                    functions.append(node.name)
            elif isinstance(node, ast.ClassDef):
                classes.append(node.name)
    except SyntaxError:
        pass

    # API маршруты через декораторы @router.get/post/put/delete/patch
    for m in re.finditer(r'@router\.(get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', src):
        routes.append(f"{m.group(1).upper()} {m.group(2)}")

    return {
        "functions": sorted(set(functions)),
        "classes":   sorted(set(classes)),
        "routes":    sorted(set(routes)),
    }


def build_snapshot() -> dict:
    snapshot = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "files": {},
    }

    for scan_dir in SCAN_DIRS:
        if not scan_dir.exists():
            continue
        for py_file in sorted(scan_dir.rglob("*.py")):
            if any(p in py_file.parts for p in SKIP_DIRS):
                continue
            symbols = extract_symbols(py_file)
            if any(symbols.values()):
                snapshot["files"][str(py_file.relative_to(ROOT))] = symbols

    return snapshot


if __name__ == "__main__":
    snap = build_snapshot()
    SNAPSHOT_FILE.write_text(json.dumps(snap, indent=2, ensure_ascii=False))

    total_files = len(snap["files"])
    total_fns   = sum(len(v["functions"]) for v in snap["files"].values())
    total_cls   = sum(len(v["classes"])   for v in snap["files"].values())
    total_rt    = sum(len(v["routes"])    for v in snap["files"].values())

    print(f"Снимок сохранён: {SNAPSHOT_FILE}")
    print(f"  Файлов: {total_files}")
    print(f"  Функций: {total_fns}")
    print(f"  Классов: {total_cls}")
    print(f"  API маршрутов: {total_rt}")
