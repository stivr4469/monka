"""
GET /api/v1/workers/health — статус всех 44 воркеров в реальном времени.

Для каждого воркера показывает:
  - status: ok | degraded | offline
  - binary_ok / pkg_ok / api_key_ok: доступность зависимостей
  - last_run: когда последний раз воркер успешно создал событие в БД
  - missing: список конкретно чего не хватает
"""
from __future__ import annotations

import importlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Загружаем .env файлы — core/.env + root/.env — в словарь для _env()
_ENV_OVERRIDES: dict[str, str] = {}

def _load_env_overrides() -> dict[str, str]:
    try:
        from dotenv import dotenv_values
    except ImportError:
        return {}
    result: dict[str, str] = {}
    # Ищем .env начиная от этого файла вверх по дереву
    here = Path(__file__).resolve()
    for parent in [here.parents[4], here.parents[5], Path("/home/zastone/study/Monitoring_utechek/core")]:
        env_file = parent / ".env"
        if env_file.exists():
            for k, v in dotenv_values(env_file).items():
                if v and k not in result:
                    result[k] = v
    return result

_ENV_OVERRIDES = _load_env_overrides()

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import CurrentUser, DBDep
from app.models.event import Event

router = APIRouter(prefix="/workers", tags=["workers"])

_GO_BIN = str(Path.home() / "go" / "bin")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _bin(name: str) -> bool:
    return bool(shutil.which(name) or shutil.which(name, path=_GO_BIN))


def _pkg(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        return False


def _env(key: str) -> bool:
    val = os.environ.get(key) or _ENV_OVERRIDES.get(key, "")
    return bool(val.strip())


# ─── Worker definitions ──────────────────────────────────────────────────────

# Каждый воркер описан словарём:
#   name         — человекочитаемое имя
#   source_names — список source_name которые воркер пишет в events.source_name
#   bins         — список нужных бинарей
#   pkgs         — список нужных Python пакетов
#   api_keys     — список env-переменных (хотя бы одно значение = ключ задан)
#   note         — краткое описание что делает воркер

_WORKERS: list[dict[str, Any]] = [
    {
        "id": "subfinder",
        "name": "Subfinder — поиск поддоменов",
        "source_names": ["subfinder"],
        "bins": ["subfinder"],
        "pkgs": [],
        "api_keys": [],
        "note": "Перечисляет поддомены через пассивные источники (DNS, CT-логи, Shodan и др.)",
    },
    {
        "id": "nuclei",
        "name": "Nuclei — сканер уязвимостей",
        "source_names": ["nuclei"],
        "bins": ["nuclei"],
        "pkgs": [],
        "api_keys": [],
        "note": "Проверяет HTTP-заголовки, CVE, мисконфигурации по шаблонам Nuclei",
    },
    {
        "id": "gitleaks",
        "name": "Gitleaks — секреты в git",
        "source_names": ["gitleaks"],
        "bins": ["gitleaks"],
        "pkgs": [],
        "api_keys": [],
        "note": "Сканирует git-репозитории на утечки API-ключей, паролей и токенов",
    },
    {
        "id": "katana",
        "name": "Katana — веб-краулер",
        "source_names": ["katana"],
        "bins": ["katana"],
        "pkgs": [],
        "api_keys": [],
        "note": "Обходит сайт как браузер, находит скрытые пути и формы",
    },
    {
        "id": "gowitness",
        "name": "Gowitness — скриншоты сайтов",
        "source_names": ["gowitness"],
        "bins": ["gowitness"],
        "pkgs": [],
        "api_keys": [],
        "note": "Делает скриншоты веб-страниц для визуального контроля",
    },
    {
        "id": "masscan",
        "name": "Masscan — быстрое сканирование портов",
        "source_names": ["masscan"],
        "bins": ["masscan"],
        "pkgs": [],
        "api_keys": [],
        "note": "Сверхбыстрый сканер портов (миллионы портов/сек), требует root",
    },
    {
        "id": "port_scanner",
        "name": "Nmap — глубокое сканирование портов",
        "source_names": ["nmap"],
        "bins": ["nmap"],
        "pkgs": [],
        "api_keys": [],
        "note": "Определяет открытые порты и версии сервисов через Nmap",
    },
    {
        "id": "certstream_monitor",
        "name": "CertStream — Certificate Transparency",
        "source_names": ["certstream_live", "google_ct_fallback"],
        "bins": [],
        "pkgs": ["certstream"],
        "api_keys": [],
        "note": "Мониторит новые SSL-сертификаты в реальном времени, находит новые поддомены",
    },
    {
        "id": "ct_monitor",
        "name": "CT Monitor — crt.sh поиск",
        "source_names": ["ct_monitor"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Ищет сертификаты домена в crt.sh и certspotter, находит скрытые поддомены",
    },
    {
        "id": "holehe_scanner",
        "name": "Holehe — регистрация email на сервисах",
        "source_names": ["holehe"],
        "bins": [],
        "pkgs": ["holehe"],
        "api_keys": [],
        "note": "Проверяет к каким онлайн-сервисам зарегистрирован email сотрудников",
    },
    {
        "id": "github_search",
        "name": "GitHub Search — утечки кода",
        "source_names": ["github-search-worker"],
        "bins": [],
        "pkgs": [],
        "api_keys": ["GITHUB_TOKEN"],
        "note": "Ищет в GitHub публично выложенный код компании (ключи, конфиги, внутренние домены)",
    },
    {
        "id": "dumpster_diver",
        "name": "DumpsterDiver — энтропийный анализ файлов",
        "source_names": ["dumpster_diver"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Находит секреты в файлах по Shannon entropy ≥ 4.0 (API-ключи, пароли)",
    },
    {
        "id": "shodan_enricher",
        "name": "Shodan — обогащение данных об IP",
        "source_names": ["shodan"],
        "bins": [],
        "pkgs": ["shodan"],
        "api_keys": ["SHODAN_API_KEY"],
        "note": "Получает из Shodan информацию об открытых портах, баннерах и уязвимостях IP",
    },
    {
        "id": "censys_enricher",
        "name": "Censys — обогащение через Censys Search",
        "source_names": ["censys"],
        "bins": [],
        "pkgs": ["censys"],
        "api_keys": ["CENSYS_API_ID"],
        "note": "Запрашивает Censys Search API для поиска хостов компании в интернете",
    },
    {
        "id": "s3_scanner",
        "name": "S3 Scanner — открытые облачные бакеты",
        "source_names": ["s3_scanner"],
        "bins": [],
        "pkgs": ["boto3"],
        "api_keys": [],
        "note": "Ищет S3/GCS/Azure бакеты домена и проверяет их на публичный доступ",
    },
    {
        "id": "ransomware_sites",
        "name": "Ransomware Sites — мониторинг leak-сайтов",
        "source_names": ["ransomware_sites", "ransomwatch"],
        "bins": ["tor"],
        "pkgs": ["playwright"],
        "api_keys": [],
        "note": "Проверяет 11 ransomware leak-сайтов (LockBit3, Akira, Hunters и др.) через Tor",
    },
    {
        "id": "darknet_monitor",
        "name": "Darknet Monitor — поиск в даркнете",
        "source_names": ["ahmia", "darksearch"],
        "bins": ["tor"],
        "pkgs": ["stem"],
        "api_keys": [],
        "note": "Ищет упоминания компании на darknet-площадках через Tor (Ahmia, DarkSearch)",
    },
    {
        "id": "stealer_parser",
        "name": "Stealer Parser — анализ стилер-логов",
        "source_names": ["stealer-parser"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Разбирает загруженные архивы стилер-логов, извлекает скомпрометированные куки и пароли",
    },
    {
        "id": "stealer_sources",
        "name": "Stealer Sources — автозагрузка из Telegram",
        "source_names": [],
        "bins": [],
        "pkgs": ["telethon"],
        "api_keys": ["TELEGRAM_API_ID", "TELEGRAM_API_HASH"],
        "note": "Автоматически скачивает свежие стилер-логи из Telegram-каналов",
    },
    {
        "id": "stealer_tg_channels",
        "name": "Stealer TG Channels — мониторинг TG каналов",
        "source_names": [],
        "bins": [],
        "pkgs": ["telethon"],
        "api_keys": ["TELEGRAM_API_ID", "TELEGRAM_API_HASH"],
        "note": "Слушает Telegram-каналы с утечками в реальном времени",
    },
    {
        "id": "cookie_validator",
        "name": "Cookie Validator — проверка актуальности куки",
        "source_names": ["cookie-validator"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Проверяет найденные сессионные куки — живые они или уже истекли",
    },
    {
        "id": "phishing_detector",
        "name": "Phishing Detector — фишинговые домены",
        "source_names": ["phishing_detector"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Ищет тайпсквоттинг и фишинговые домены, имитирующие бренд (URLhaus, OpenPhish)",
    },
    {
        "id": "takeover_detector",
        "name": "Takeover Detector — захват поддоменов",
        "source_names": ["takeover_detector"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Проверяет DNS-записи поддоменов на признаки subdomain takeover",
    },
    {
        "id": "tls_fingerprinter",
        "name": "TLS Fingerprinter — анализ TLS",
        "source_names": ["tls_fingerprinter"],
        "bins": [],
        "pkgs": ["cryptography"],
        "api_keys": [],
        "note": "Проверяет TLS-сертификаты: срок, алгоритм, цепочку доверия, HSTS, JA3",
    },
    {
        "id": "domain_hardening",
        "name": "Domain Hardening — почтовые политики",
        "source_names": ["domain_hardening"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Проверяет SPF, DMARC, DKIM, MX и DNSSEC на отсутствие мисконфигураций",
    },
    {
        "id": "whois_monitor",
        "name": "WHOIS Monitor — изменения регистранта",
        "source_names": ["whois_monitor"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Следит за изменениями RDAP/WHOIS данных домена (смена владельца, серверов)",
    },
    {
        "id": "bgp_monitor",
        "name": "BGP Monitor — изменения маршрутизации",
        "source_names": ["bgp_monitor"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Детектирует смену провайдера и IP-диапазонов через BGPView API",
    },
    {
        "id": "beaconing_detector",
        "name": "Beaconing Detector — периодические обращения",
        "source_names": ["beaconing_detector"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Анализирует паттерны DNS-запросов, выявляет признаки C2-beaconing",
    },
    {
        "id": "brand_monitor",
        "name": "Brand Monitor — упоминания бренда",
        "source_names": ["telegram_brand_monitor"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Ищет упоминания компании в Reddit, Hacker News и Telegram",
    },
    {
        "id": "paste_monitor",
        "name": "Paste Monitor — утечки на Pastebin",
        "source_names": ["pastebin", "pastee"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Мониторит Pastebin и Pastee.ee на публикации с данными компании",
    },
    {
        "id": "mobile_monitor",
        "name": "Mobile Monitor — приложения в сторах",
        "source_names": ["mobile_monitor"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Отслеживает мобильные приложения бренда в App Store и Google Play",
    },
    {
        "id": "human_osint",
        "name": "Human OSINT — профиль сотрудников",
        "source_names": ["github_osint", "linkedin_osint", "linkedin_ddg"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Собирает публичные данные о сотрудниках (GitHub активность, LinkedIn профили)",
    },
    {
        "id": "tech_profiler",
        "name": "Tech Profiler — стек технологий",
        "source_names": ["tech_profiler"],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Определяет технологии сайта (CMS, фреймворки, серверы, CDN) как Wappalyzer",
    },
    {
        "id": "intelx_api",
        "name": "IntelX — поиск в Intelligence X",
        "source_names": ["IntelX"],
        "bins": [],
        "pkgs": [],
        "api_keys": ["INTELX_API_KEY"],
        "note": "Ищет утечки данных через Intelligence X (тёмные форумы, Tor, I2P)",
    },
    {
        "id": "stix_export",
        "name": "STIX Export — экспорт угроз",
        "source_names": [],
        "bins": [],
        "pkgs": ["stix2"],
        "api_keys": [],
        "note": "Экспортирует события в формат STIX 2.1 для SIEM-интеграций",
    },
    {
        "id": "breach_checker",
        "name": "Breach Checker — проверка утечек HIBP",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Проверяет email сотрудников через HaveIBeenPwned (без ключа — ограниченный доступ)",
    },
    {
        "id": "telegram_monitor",
        "name": "Telegram Monitor — мониторинг TG",
        "source_names": [],
        "bins": [],
        "pkgs": ["telethon"],
        "api_keys": ["TELEGRAM_BOT_TOKEN"],
        "note": "Слушает Telegram каналы и группы на упоминания компании",
    },
    {
        "id": "telegram_alerts",
        "name": "Telegram Alerts — уведомления в бот",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": ["TELEGRAM_BOT_TOKEN"],
        "note": "Отправляет уведомления о новых угрозах в Telegram-бот",
    },
    {
        "id": "tor_client",
        "name": "Tor Client — анонимные запросы",
        "source_names": [],
        "bins": ["tor"],
        "pkgs": ["stem"],
        "api_keys": [],
        "note": "Базовый Tor-клиент через SOCKS5 :9050 для доступа к .onion ресурсам",
    },
    {
        "id": "attribution_engine",
        "name": "Attribution Engine — компания → ASN → CIDR",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Определяет все IP-диапазоны компании через BGPView: домен → ASN → CIDR-блоки",
    },
    {
        "id": "ai_narrative",
        "name": "AI Narrative — executive summary",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": ["ANTHROPIC_API_KEY"],
        "note": "Генерирует текстовый executive summary угроз через Claude AI",
    },
    {
        "id": "remediation_hints",
        "name": "Remediation Hints — рекомендации по устранению",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Добавляет к событиям конкретные шаги по устранению уязвимостей",
    },
    {
        "id": "ticketing",
        "name": "Ticketing — Jira/ServiceNow интеграция",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Создаёт тикеты в Jira или ServiceNow для критических событий",
    },
    {
        "id": "bulk_ingest",
        "name": "Bulk Ingest — массовая загрузка данных",
        "source_names": [],
        "bins": [],
        "pkgs": [],
        "api_keys": [],
        "note": "Принимает и обрабатывает массовые потоки событий от внешних источников",
    },
]


# ─── Pydantic-схемы ──────────────────────────────────────────────────────────

class WorkerStatus(BaseModel):
    id: str
    name: str
    note: str
    status: str          # ok | degraded | offline
    binary_ok: bool
    pkg_ok: bool
    api_key_ok: bool
    missing: list[str]   # конкретный список чего не хватает
    last_run: datetime | None
    last_source: str | None


class WorkersHealthResponse(BaseModel):
    checked_at: datetime
    total: int
    ok: int
    degraded: int
    offline: int
    workers: list[WorkerStatus]


# ─── Endpoint ────────────────────────────────────────────────────────────────

@router.get(
    "/health",
    response_model=WorkersHealthResponse,
    summary="Статус всех воркеров — бинари, пакеты, ключи, последний запуск",
)
async def workers_health(
    db: DBDep,
    current_user: CurrentUser,
) -> WorkersHealthResponse:
    # Получаем последнее событие для каждого source_name из БД
    rows = await db.execute(
        select(Event.source_name, func.max(Event.detected_at).label("last_at"))
        .group_by(Event.source_name)
    )
    last_by_source: dict[str, datetime] = {r.source_name: r.last_at for r in rows}

    statuses: list[WorkerStatus] = []
    now = datetime.now(timezone.utc)

    for w in _WORKERS:
        missing: list[str] = []

        # Проверка бинарей
        for b in w["bins"]:
            if not _bin(b):
                missing.append(f"binary:{b}")

        # Проверка пакетов
        for p in w["pkgs"]:
            if not _pkg(p):
                missing.append(f"pkg:{p}")

        # Проверка API-ключей
        for k in w["api_keys"]:
            if not _env(k):
                missing.append(f"env:{k}")

        binary_ok = not any(m.startswith("binary:") for m in missing)
        pkg_ok    = not any(m.startswith("pkg:") for m in missing)
        api_ok    = not any(m.startswith("env:") for m in missing)

        # Последний запуск — берём самое свежее из всех source_names воркера
        last_run: datetime | None = None
        last_source: str | None = None
        for sn in w["source_names"]:
            t = last_by_source.get(sn)
            if t and (last_run is None or t > last_run):
                last_run = t
                last_source = sn

        # Статус
        if not missing:
            status = "ok"
        elif binary_ok and pkg_ok:
            # Нет только опциональных ключей — воркер работает в ограниченном режиме
            status = "degraded"
        else:
            status = "offline"

        statuses.append(WorkerStatus(
            id=w["id"],
            name=w["name"],
            note=w["note"],
            status=status,
            binary_ok=binary_ok,
            pkg_ok=pkg_ok,
            api_key_ok=api_ok,
            missing=missing,
            last_run=last_run,
            last_source=last_source,
        ))

    ok_count       = sum(1 for s in statuses if s.status == "ok")
    degraded_count = sum(1 for s in statuses if s.status == "degraded")
    offline_count  = sum(1 for s in statuses if s.status == "offline")

    return WorkersHealthResponse(
        checked_at=now,
        total=len(statuses),
        ok=ok_count,
        degraded=degraded_count,
        offline=offline_count,
        workers=statuses,
    )
