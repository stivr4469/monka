"""
Мониторинг Telegram-каналов со стилер-логами через Telethon (MTProto).

Почему не t.me/s/ (веб-скрейпинг):
  - Большинство каналов со стилерами не имеют публичной истории сообщений
    → t.me/s/channel редиректит на t.me/channel, посты недоступны
  - Реальные логи шарятся как файловые вложения (ZIP/TXT), а не текст постов
  - Текстовый скрейпинг t.me/s/ не даёт учётных данных

Для работы нужно:
  1. Получить API_ID и API_HASH на https://my.telegram.org
  2. Установить: pip install telethon
  3. Добавить в core/.env:
       TELEGRAM_API_ID=12345678
       TELEGRAM_API_HASH=abcdef1234567890abcdef1234567890
  4. Первый запуск создаст файл сессии (одноразовая авторизация по SMS)

Известные каналы со стилер-логами (проверять актуальность):
  Файловые дампы:
    @freelogs_shop, @stealerlogs, @freeclouds, @logs_mafia
    @raccoon_logs_free, @redline_logs_free, @vidar_logs_channel
    @LummaC2Logs, @MetaStealer_logs, @StealC_logs
  Combo-листы:
    @freecombolist, @combo_logs_free, @logs_free_club
    @freeredlinelogs, @leakednation

  Большинство реальных каналов — приватные или со скрытой историей.
  Доступ возможен только через полноценный Telegram-клиент (Telethon/Pyrogram).
"""
import logging
import os
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

STEALER_TG_CHANNELS: list[str] = [
    "freelogs_shop",
    "stealerlogs",
    "freeclouds",
    "logs_mafia",
    "freecombolist",
    "combo_logs_free",
    "logs_free_club",
    "freeredlinelogs",
    "redline_logs_free",
    "raccoon_logs_free",
    "vidar_logs_channel",
    "LummaC2Logs",
    "MetaStealer_logs",
    "StealC_logs",
    "leakednation",
    # Добавлены по результатам проверки доступности (май 2026)
    "logs_cloud",
    "cloudlogs_free",
    "free_logs_daily",
    "InfoStealer_News",
]

_TELETHON_AVAILABLE = False

try:
    from telethon.sync import TelegramClient
    from telethon import events
    _TELETHON_AVAILABLE = True
except ImportError:
    pass

# 5c: импорт на уровне модуля, вне цикла
try:
    from stealer_parser import parse_stealer_log as _parse_stealer_log  # type: ignore[import]
    _STEALER_PARSER_AVAILABLE = True
except ImportError:
    _STEALER_PARSER_AVAILABLE = False
    _parse_stealer_log = None  # type: ignore[assignment]


def _check_setup() -> str | None:
    """Возвращает строку с описанием проблемы или None если всё готово."""
    if not _TELETHON_AVAILABLE:
        return "telethon не установлен: pip install telethon"
    if not os.getenv("TELEGRAM_API_ID"):
        return "нет TELEGRAM_API_ID в .env (получить на https://my.telegram.org)"
    if not os.getenv("TELEGRAM_API_HASH"):
        return "нет TELEGRAM_API_HASH в .env (получить на https://my.telegram.org)"
    return None


def scan_tg_stealer_channels(
    domain: str,
    core_api_url: str,
    internal_secret: str,
    extra_channels: list[str] | None = None,
) -> dict:
    """
    Сканирует Telegram-каналы через Telethon.
    Возвращает сводку: {channel: {posts, matched, sent, errors}} или
    {"error": "причина"} если Telethon не настроен.
    """
    problem = _check_setup()
    if problem:
        logger.warning("[tg-stealer] Недоступен: %s", problem)
        return {"error": problem, "setup_required": True}

    api_id   = int(os.getenv("TELEGRAM_API_ID"))
    api_hash = os.getenv("TELEGRAM_API_HASH")
    session  = os.getenv("TELEGRAM_SESSION_FILE", "easm_tg_session")

    channels = list(dict.fromkeys(
        STEALER_TG_CHANNELS + (extra_channels or [])
    ))

    import httpx
    from urllib.parse import urlparse

    def _domain_match(text: str, target: str) -> bool:
        import re
        for url_m in re.finditer(r'https?://([^\s/:?#]+)', text):
            host = url_m.group(1).removeprefix("www.")
            if host == target or host.endswith("." + target):
                return True
        for email_m in re.finditer(r'[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', text):
            if email_m.group(1).lower() == target:
                return True
        return False

    def _extract_creds(text: str) -> list[dict]:
        import re
        records = []
        three = re.compile(
            r'(https?://[^\s:]+)[:|]([^\s:]+):(\S{4,})'
        )
        combo = re.compile(
            r'([a-zA-Z0-9_.+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}):(\S{4,})'
        )
        for m in three.finditer(text):
            records.append({"url": m.group(1), "login": m.group(2), "password": m.group(3)})
        if not records:
            for m in combo.finditer(text):
                records.append({"url": "", "login": m.group(1), "password": m.group(2)})
        return records

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    headers    = {"Authorization": f"Bearer {internal_secret}"}
    summary    = {}

    try:
        with TelegramClient(session, api_id, api_hash) as client:
            for channel in channels:
                posts = found = matched = sent = errors = 0
                try:
                    entity = client.get_entity(channel)
                    for msg in client.iter_messages(entity, limit=100):
                        posts += 1
                        text = msg.message or ""

                        # Обрабатываем текстовые сообщения
                        recs = _extract_creds(text)
                        found += len(recs)
                        for rec in recs:
                            if not _domain_match(
                                rec.get("url", "") + " " + rec.get("login", ""),
                                domain,
                            ):
                                continue
                            matched += 1
                            event = {
                                "event_type":   "stealer_log",
                                "severity":     "critical",
                                "source_type":  "telegram_stealer",
                                "source_name":  f"tg:{channel}",
                                "target_domain": domain,
                                "payload": {**rec, "channel": channel, "msg_id": msg.id},
                            }
                            try:
                                r = httpx.post(ingest_url, json=event, headers=headers, timeout=10)
                                if r.json().get("status") in ("accepted", "duplicate"):
                                    sent += 1
                                else:
                                    errors += 1
                            except Exception as exc:
                                logger.error("[tg-stealer] ingest: %s", exc)
                                errors += 1

                        # Файловые вложения — скачиваем и парсим через stealer_parser
                        if msg.document:
                            name = ""
                            for attr in msg.document.attributes:
                                from telethon.tl.types import DocumentAttributeFilename
                                if isinstance(attr, DocumentAttributeFilename):
                                    name = attr.file_name
                            # 5a: Пропускаем файлы > 50 МБ
                            if msg.document.size > 50 * 1024 * 1024:
                                logger.warning(
                                    "[tg-stealer] @%s msg_id=%d: файл '%s' превышает 50 МБ (%d байт), пропускаем",
                                    channel, msg.id, name, msg.document.size,
                                )
                            elif name.lower().endswith((".txt", ".zip", ".log", ".csv")):
                                tmp_path: str | None = None
                                try:
                                    file_bytes = client.download_media(msg, file=bytes)
                                    if file_bytes:
                                        # 5b: bytes → Path через временный файл
                                        with tempfile.NamedTemporaryFile(
                                            suffix=Path(name).suffix or ".zip",
                                            delete=False,
                                        ) as tmp_fh:
                                            tmp_fh.write(file_bytes)
                                            tmp_path = tmp_fh.name
                                        if not _STEALER_PARSER_AVAILABLE:
                                            logger.warning("[tg-stealer] stealer_parser недоступен")
                                        else:
                                            result = _parse_stealer_log(
                                                Path(tmp_path), name, [domain],
                                                core_api_url, internal_secret,
                                            )
                                            matched += result.get("matched", 0)
                                            sent    += result.get("sent", 0)
                                            errors  += result.get("errors", 0)
                                except Exception as exc:
                                    logger.error("[tg-stealer] file download %s: %s", name, exc)
                                finally:
                                    # 5b: Удаляем временный файл
                                    if tmp_path is not None:
                                        try:
                                            os.unlink(tmp_path)
                                        except OSError:
                                            pass

                except Exception as exc:
                    logger.warning("[tg-stealer] @%s: %s", channel, exc)

                summary[channel] = {
                    "posts": posts, "found": found,
                    "matched": matched, "sent": sent, "errors": errors,
                }
                logger.info(
                    "[tg-stealer] @%s: posts=%d found=%d matched=%d sent=%d",
                    channel, posts, found, matched, sent,
                )

    except Exception as exc:
        logger.error("[tg-stealer] Ошибка клиента: %s", exc)
        return {"error": str(exc)}

    return summary
