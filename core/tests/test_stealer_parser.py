"""Тесты парсера стилер-логов."""
# sys.path для workers добавляется в conftest.py
from tasks.stealer_parser import (
    _detect_and_parse,
    _matches_target,
)


def mask_password(value: str) -> str:
    """Локальная копия — функция удалена из stealer_parser."""
    if len(value) <= 3:
        return "***"
    return value[:3] + "*" * (len(value) - 5) + value[-2:]

# ── Маскирование ──────────────────────────────────────────────────

def test_mask_short_password():
    assert mask_password("abc") == "***"

def test_mask_normal_password():
    result = mask_password("secret123")
    assert result.startswith("sec")
    assert result.endswith("23")
    assert "*" in result
    assert "secret" not in result  # сырой пароль не виден

def test_mask_empty():
    assert mask_password("") == "***"

# ── Парсинг блочного формата ──────────────────────────────────────

BLOCK_SAMPLE = """
URL: https://mail.example.com
Login: user@example.com
Password: hunter2

URL: https://bank.example.com
Login: admin@example.com
Password: qwerty123
---
URL: https://other.com
Login: someone@other.com
Password: pass456
"""

def test_parse_block_format():
    records = _detect_and_parse(BLOCK_SAMPLE.splitlines())
    assert len(records) >= 2
    assert any(r["login"] == "user@example.com" for r in records)
    assert any(r["url"] == "https://bank.example.com" for r in records)

def test_block_passwords_present():
    records = _detect_and_parse(BLOCK_SAMPLE.splitlines())
    # Убеждаемся что парсер читает пароли (маскировка — на уровне выше)
    assert any(r["password"] == "hunter2" for r in records)

# ── Парсинг combo-list ─────────────────────────────────────────────

COMBO_SAMPLE = """
user@example.com:password123
admin@company.com:admin2024
test@other.org:qwerty
"""

def test_parse_combo_format():
    records = _detect_and_parse(COMBO_SAMPLE.splitlines())
    assert len(records) == 3
    assert records[0]["login"] == "user@example.com"
    assert records[0]["password"] == "password123"

# ── Сопоставление с доменом ───────────────────────────────────────

def test_matches_by_url():
    rec = {"url": "https://mail.example.com", "login": "someone"}
    assert _matches_target(rec, "example.com") is True

def test_matches_by_email_login():
    rec = {"url": "", "login": "user@example.com"}
    assert _matches_target(rec, "example.com") is True

def test_matches_subdomain():
    rec = {"url": "https://api.sub.example.com", "login": ""}
    assert _matches_target(rec, "example.com") is True

def test_no_match_other_domain():
    rec = {"url": "https://google.com", "login": "user@google.com"}
    assert _matches_target(rec, "example.com") is False

def test_no_match_empty():
    rec = {"url": "", "login": "noatsign"}
    assert _matches_target(rec, "example.com") is False
