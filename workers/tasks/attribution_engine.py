"""
Asset Attribution Engine — автооткрытие IP-диапазонов компании.

Алгоритм:
  1. RIPE NCC Searchcomplete: название компании → список ASN
  2. Для каждого ASN: RIPE Announced Prefixes → список CIDR-блоков (IPv4+IPv6)
  3. Для каждого ASN: RIPE AS Overview → название и тип
  4. Дедупликация и подсчёт адресного пространства

API: RIPE NCC Stat (stat.ripe.net) — бесплатный, без ключей, доступен глобально.
Лимит: не указан, выдерживаем 1 req/сек для вежливости.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_RIPE_BASE = "https://stat.ripe.net/data"
_TIMEOUT   = httpx.Timeout(20.0)
_DELAY     = 1.0    # секунд между запросами
_MAX_ASNS  = 10     # максимум ASN из поискового результата


# ─────────────────────────────────────────────────────────────────────────────
# RIPE NCC helpers
# ─────────────────────────────────────────────────────────────────────────────

def search_asn_by_org(company_name: str) -> list[dict[str, Any]]:
    """
    RIPE Searchcomplete API: название компании → список ASN.

    Возвращает: [{"asn": 1234, "name": "COMPANY-AS", "country": "", "description": "..."}]
    """
    try:
        resp = httpx.get(
            f"{_RIPE_BASE}/searchcomplete/data.json",
            params={"resource": company_name},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        categories = resp.json().get("data", {}).get("categories", [])
        asns = []
        for cat in categories:
            if cat.get("category") != "ASNs":
                continue
            for suggestion in cat.get("suggestions", [])[:_MAX_ASNS]:
                label = suggestion.get("label", "")        # "AS15742"
                description = suggestion.get("description", "")
                if not label.upper().startswith("AS"):
                    continue
                try:
                    asn_num = int(label[2:])
                except ValueError:
                    continue
                asns.append({
                    "asn":         asn_num,
                    "name":        label,
                    "description": description,
                    "country":     "",
                })
        logger.info("[attribution] '%s' → %d ASN найдено", company_name, len(asns))
        return asns
    except Exception as exc:
        logger.warning("[attribution] RIPE search error for '%s': %s", company_name, exc)
        return []


def get_asn_info(asn: int) -> dict[str, Any]:
    """
    RIPE AS Overview: подробности об ASN (holder, type, country).

    Возвращает: {"asn": N, "name": "...", "country": "...", "description": "..."}
    """
    try:
        resp = httpx.get(
            f"{_RIPE_BASE}/as-overview/data.json",
            params={"resource": f"AS{asn}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        holder = data.get("holder", "")
        return {
            "asn":         asn,
            "name":        f"AS{asn}",
            "description": holder,
            "country":     "",
        }
    except Exception as exc:
        logger.debug("[attribution] AS overview error for AS%s: %s", asn, exc)
        return {"asn": asn, "name": f"AS{asn}", "description": "", "country": ""}


def get_asn_prefixes(asn: int) -> list[dict[str, Any]]:
    """
    RIPE Announced Prefixes: ASN → список CIDR-блоков (IPv4 only).

    Возвращает: [{"prefix": "185.12.0.0/22", "description": "", "country": "", "asn": N}]
    """
    try:
        resp = httpx.get(
            f"{_RIPE_BASE}/announced-prefixes/data.json",
            params={"resource": f"AS{asn}"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        prefixes_raw = resp.json().get("data", {}).get("prefixes", [])
        result = []
        for p in prefixes_raw:
            prefix = p.get("prefix", "")
            if not prefix:
                continue
            # Только IPv4
            try:
                if ":" in prefix:   # IPv6 — пропускаем
                    continue
                ipaddress.IPv4Network(prefix, strict=False)
            except ValueError:
                continue
            result.append({
                "prefix":      prefix,
                "description": "",
                "country":     "",
                "asn":         asn,
            })
        return result
    except Exception as exc:
        logger.warning("[attribution] RIPE prefixes error for AS%s: %s", asn, exc)
        return []


def _count_ips(prefix: str) -> int:
    """Количество IP-адресов в CIDR-блоке."""
    try:
        return ipaddress.IPv4Network(prefix, strict=False).num_addresses
    except ValueError:
        return 0


def lookup_asn_by_domain(domain: str) -> list[dict[str, Any]]:
    """
    Fallback: резолвим домен → IP → RIPE prefix-overview → ASN.

    Используется если text search не нашёл ASN по названию компании.
    Возвращает: [{"asn": N, "name": "...", "description": "...", "country": ""}]
    """
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        logger.debug("[attribution] Не удалось резолвить %s", domain)
        return []

    try:
        resp = httpx.get(
            f"{_RIPE_BASE}/prefix-overview/data.json",
            params={"resource": ip},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        asns_raw = resp.json().get("data", {}).get("asns", [])
        result = []
        for a in asns_raw:
            asn = a.get("asn")
            holder = a.get("holder", "")
            if asn:
                result.append({
                    "asn":         asn,
                    "name":        f"AS{asn}",
                    "description": holder,
                    "country":     "",
                })
        logger.info("[attribution] domain=%s ip=%s → %d ASN (fallback)", domain, ip, len(result))
        return result
    except Exception as exc:
        logger.debug("[attribution] RIPE prefix-overview error for %s: %s", ip, exc)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Основная функция
# ─────────────────────────────────────────────────────────────────────────────

def run_attribution(
    company_name: str,
    domain: str | None = None,
) -> dict[str, Any]:
    """
    Полный Attribution: название компании → ASN → CIDR-блоки.

    Использует RIPE NCC Stat API (бесплатный, без ключей).

    Возвращает структурированный отчёт:
    {
        "company_name": "...",
        "domain": "...",
        "asns": [{"asn": N, "name": "...", "description": "...", "country": "..."}],
        "cidrs": [{"prefix": "x.x.x.x/y", "asn": N, "description": "..."}],
        "total_prefixes": N,
        "total_ips": M,
    }
    """
    logger.info("[attribution] Старт: company='%s' domain=%s", company_name, domain)

    # 1. Поиск ASN по названию компании через RIPE text search
    asns = search_asn_by_org(company_name)

    # Fallback: если text search не нашёл — резолвим домен → IP → RIPE prefix lookup
    if not asns and domain:
        logger.info("[attribution] Text search не дал результата, пробуем domain fallback")
        asns = lookup_asn_by_domain(domain)

    if not asns:
        logger.info("[attribution] ASN не найдены для '%s'", company_name)
        return {
            "company_name":   company_name,
            "domain":         domain,
            "asns":           [],
            "cidrs":          [],
            "total_prefixes": 0,
            "total_ips":      0,
        }

    time.sleep(_DELAY)

    # 2. Обогащаем ASN детальной информацией + получаем CIDR-блоки
    enriched_asns: list[dict[str, Any]] = []
    all_cidrs: list[dict[str, Any]] = []
    seen_prefixes: set[str] = set()

    for asn_obj in asns:
        asn = asn_obj.get("asn")
        if not asn:
            continue

        # Детальная информация об ASN
        info = get_asn_info(asn)
        enriched = {**asn_obj, **info}
        enriched_asns.append(enriched)
        time.sleep(_DELAY)

        # CIDR-блоки
        prefixes = get_asn_prefixes(asn)
        for cidr in prefixes:
            pfx = cidr["prefix"]
            if pfx not in seen_prefixes:
                seen_prefixes.add(pfx)
                all_cidrs.append(cidr)

        logger.info(
            "[attribution] AS%s (%s): %d CIDR-блоков",
            asn, info.get("description", "")[:40], len(prefixes),
        )
        time.sleep(_DELAY)

    # 3. Считаем общее адресное пространство
    total_ips = sum(_count_ips(c["prefix"]) for c in all_cidrs)

    logger.info(
        "[attribution] Итого: company='%s' asns=%d cidrs=%d ips=%d",
        company_name, len(enriched_asns), len(all_cidrs), total_ips,
    )

    return {
        "company_name":   company_name,
        "domain":         domain,
        "asns":           enriched_asns,
        "cidrs":          all_cidrs,
        "total_prefixes": len(all_cidrs),
        "total_ips":      total_ips,
    }
