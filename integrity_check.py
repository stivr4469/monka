"""
Сравнивает текущий код со снимком integrity_manifest.json.
Показывает что пропало, что добавилось.
Запускать после редактирования:
    python3 integrity_check.py
"""
import json
import sys
from pathlib import Path

ROOT          = Path(__file__).parent
SNAPSHOT_FILE = ROOT / "integrity_manifest.json"

# Импортируем builder из snapshot-скрипта
sys.path.insert(0, str(ROOT))
from integrity_snapshot import build_snapshot


def compare(old: dict, new: dict) -> tuple[list, list]:
    """Возвращает (lost, added) — списки строк."""
    lost, added = [], []

    all_files = set(old["files"]) | set(new["files"])

    for f in sorted(all_files):
        old_sym = old["files"].get(f, {"functions": [], "classes": [], "routes": []})
        new_sym = new["files"].get(f, {"functions": [], "classes": [], "routes": []})

        for kind in ("functions", "classes", "routes"):
            old_set = set(old_sym[kind])
            new_set = set(new_sym[kind])
            for item in sorted(old_set - new_set):
                lost.append(f"  ПОТЕРЯНО  [{kind[:-1]}] {f} :: {item}")
            for item in sorted(new_set - old_set):
                added.append(f"  ДОБАВЛЕНО [{kind[:-1]}] {f} :: {item}")

    return lost, added


if __name__ == "__main__":
    if not SNAPSHOT_FILE.exists():
        print("Снимок не найден. Сначала запусти: python3 integrity_snapshot.py")
        sys.exit(1)

    old_snap = json.loads(SNAPSHOT_FILE.read_text())
    new_snap = build_snapshot()

    lost, added = compare(old_snap, new_snap)

    if not lost and not added:
        print("✅ Целостность кода подтверждена — ничего не потеряно и не добавлено.")
        sys.exit(0)

    if lost:
        print(f"\n🔴 ПОТЕРЯНО ({len(lost)}):")
        for line in lost:
            print(line)

    if added:
        print(f"\n🟢 ДОБАВЛЕНО ({len(added)}):")
        for line in added:
            print(line)

    if lost:
        print("\n⚠️  Есть потери! Проверь git diff или восстанови из git stash.")
        sys.exit(1)
    else:
        print("\n✅ Потерь нет. Только новые добавления.")
        sys.exit(0)
