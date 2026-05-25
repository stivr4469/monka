"""
Воркер Domain Hardening — проверка периметра домена.

Проверки:
  1. SPF    — наличие TXT-записи v=spf1 на apex-домене
  2. DMARC  — TXT-запись на _dmarc.<domain>
  3. AXFR   — попытка DNS Zone Transfer (разглашение всех записей зоны)
  4. SSL    — просроченный или отсутствующий TLS-сертификат

Каждая проблема → NormalizedEvent(event_type="vulnerability", source_name="domain_hardening")
"""
import logging
import socket
import ssl
from datetime import datetime, timezone

import dns.exception
import dns.query
import dns.resolver
import dns.zone
import httpx

logger = logging.getLogger(__name__)

# Таймаут DNS-запросов (секунды)
_DNS_TIMEOUT = 5.0

# Таймаут HTTP/HTTPS-запросов
_HTTP_TIMEOUT = 10.0

# Отображение проблемы на severity
_ISSUE_SEVERITY: dict[str, str] = {
    "no_spf":          "medium",
    "no_dmarc":        "medium",
    "axfr_allowed":    "high",
    "ssl_expired":     "critical",
    "ssl_missing":     "high",
    "ssl_expiring_soon": "medium",
}

# Предупреждение за N дней до истечения сертификата
_SSL_WARN_DAYS = 30

# Статусы Core API, считающиеся успешной доставкой
_INGEST_OK = frozenset({"accepted", "duplicate"})


# ──────────────────────────────────────────────
# Отдельные проверки
# ──────────────────────────────────────────────

_PUBLIC_DNS = ["8.8.8.8", "8.8.4.4"]


def _make_resolver() -> dns.resolver.Resolver:
    """Создаёт резолвер с публичными DNS-серверами (не системный)."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = _PUBLIC_DNS
    r.lifetime = _DNS_TIMEOUT
    return r


def _check_spf(domain: str) -> list[dict]:
    """Проверяет наличие SPF TXT-записи на apex-домене."""
    issues = []
    try:
        answers = _make_resolver().resolve(domain, "TXT")
        has_spf = any(
            b"v=spf1" in rdata.to_text().encode()
            for rdata in answers
        )
        if not has_spf:
            issues.append({
                "check": "no_spf",
                "description": f"Нет SPF-записи для {domain}. Email-спуфинг возможен.",
                "severity": _ISSUE_SEVERITY["no_spf"],
            })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        issues.append({
            "check": "no_spf",
            "description": f"Нет TXT-записей / домен не существует: {domain}. SPF не настроен.",
            "severity": _ISSUE_SEVERITY["no_spf"],
        })
    except Exception as exc:
        # SERVFAIL, таймаут, сетевая ошибка — не создаём ложный алерт
        logger.warning("[hardening][spf] %s: DNS ошибка — %s", domain, exc)
    return issues


def _check_dmarc(domain: str) -> list[dict]:
    """Проверяет наличие DMARC TXT-записи на _dmarc.<domain>."""
    issues = []
    dmarc_host = f"_dmarc.{domain}"
    try:
        answers = _make_resolver().resolve(dmarc_host, "TXT")
        has_dmarc = any(
            b"v=DMARC1" in rdata.to_text().encode()
            for rdata in answers
        )
        if not has_dmarc:
            issues.append({
                "check": "no_dmarc",
                "description": f"Нет DMARC-записи для {dmarc_host}.",
                "severity": _ISSUE_SEVERITY["no_dmarc"],
            })
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        issues.append({
            "check": "no_dmarc",
            "description": f"Запись {dmarc_host} отсутствует. DMARC не настроен.",
            "severity": _ISSUE_SEVERITY["no_dmarc"],
        })
    except Exception as exc:
        logger.debug("[hardening][dmarc] %s: %s", domain, exc)
    return issues


def _check_axfr(domain: str) -> list[dict]:
    """Пробует AXFR (Zone Transfer) — если разрешено, серьёзная утечка конфигурации."""
    issues = []
    try:
        ns_answers = _make_resolver().resolve(domain, "NS")
        ns_hosts = [str(ns).rstrip(".") for ns in ns_answers]

        for ns_host in ns_hosts[:3]:  # проверяем максимум 3 NS
            try:
                ns_ip = socket.gethostbyname(ns_host)
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=_DNS_TIMEOUT, lifetime=_DNS_TIMEOUT)
                )
                if zone:
                    issues.append({
                        "check": "axfr_allowed",
                        "description": (
                            f"DNS Zone Transfer (AXFR) разрешён на {ns_host} для {domain}. "
                            f"Полная DNS-конфигурация зоны доступна публично."
                        ),
                        "severity": _ISSUE_SEVERITY["axfr_allowed"],
                        "ns_host": ns_host,
                    })
                    break
            except Exception:
                pass  # AXFR запрещён — это нормально
    except Exception as exc:
        logger.debug("[hardening][axfr] %s: %s", domain, exc)
    return issues


def _check_ssl(domain: str) -> list[dict]:
    """Проверяет срок действия SSL-сертификата на порту 443."""
    issues = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=_HTTP_TIMEOUT),
            server_hostname=domain,
        ) as ssock:
            cert = ssock.getpeercert()
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                days_left = (not_after - now).days

                if days_left < 0:
                    issues.append({
                        "check": "ssl_expired",
                        "description": f"SSL-сертификат {domain} истёк {not_after.date()} (просрочен {-days_left} дн.).",
                        "severity": _ISSUE_SEVERITY["ssl_expired"],
                        "expires": not_after.isoformat(),
                        "days_left": days_left,
                    })
                elif days_left < _SSL_WARN_DAYS:
                    issues.append({
                        "check": "ssl_expiring_soon",
                        "description": f"SSL-сертификат {domain} истекает через {days_left} дн. ({not_after.date()}).",
                        "severity": _ISSUE_SEVERITY["ssl_expiring_soon"],
                        "expires": not_after.isoformat(),
                        "days_left": days_left,
                    })
    except ssl.SSLCertVerificationError as exc:
        issues.append({
            "check": "ssl_missing",
            "description": f"SSL-сертификат {domain} не прошёл верификацию: {exc}",
            "severity": _ISSUE_SEVERITY["ssl_missing"],
        })
    except (ConnectionRefusedError, socket.timeout, OSError):
        # HTTPS не доступен — тоже проблема
        issues.append({
            "check": "ssl_missing",
            "description": f"HTTPS недоступен для {domain} (порт 443 закрыт или timeout).",
            "severity": _ISSUE_SEVERITY["ssl_missing"],
        })
    except Exception as exc:
        logger.debug("[hardening][ssl] %s: %s", domain, exc)
    return issues


# ──────────────────────────────────────────────
# Основная функция
# ──────────────────────────────────────────────

def run_domain_hardening(
    domain: str,
    core_api_url: str,
    internal_secret: str,
) -> dict:
    """
    Запускает все проверки периметра для домена.
    Каждая найденная проблема отправляется в Core API как событие.

    Возвращает: {"checks": N, "issues": M, "sent": K}
    """
    domain = domain.strip().lower()
    logger.info("[hardening] Начало проверки периметра domain=%s", domain)

    ingest_url = f"{core_api_url}/api/v1/internal/ingest"
    headers = {"Authorization": f"Bearer {internal_secret}"}

    # Запускаем все проверки
    all_issues: list[dict] = []
    for check_fn in (_check_spf, _check_dmarc, _check_axfr, _check_ssl):
        try:
            all_issues.extend(check_fn(domain))
        except Exception as exc:
            logger.error("[hardening][%s] Неожиданная ошибка: %s", check_fn.__name__, exc)

    sent = 0
    for issue in all_issues:
        event = {
            "event_type": "vulnerability",
            "severity": issue["severity"],
            "source_type": "nuclei",  # используем nuclei как ближайший SourceType для периметра
            "source_name": "domain_hardening",
            "target_domain": domain,
            "payload": {
                "check": issue["check"],
                "description": issue["description"],
                **{k: v for k, v in issue.items() if k not in ("check", "description", "severity")},
            },
        }
        try:
            r = httpx.post(ingest_url, json=event, headers=headers, timeout=_HTTP_TIMEOUT)
            if r.json().get("status") in _INGEST_OK:
                sent += 1
        except Exception as exc:
            logger.error("[hardening] Ошибка отправки события: %s", exc)

    logger.info(
        "[hardening] Итого domain=%s checks=4 issues=%d sent=%d",
        domain, len(all_issues), sent,
    )
    return {"checks": 4, "issues": len(all_issues), "sent": sent}
