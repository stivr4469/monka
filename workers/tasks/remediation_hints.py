"""
Remediation hints — советы по устранению для каждого типа события.
Маппинг EventType → список actionable шагов.
"""

REMEDIATION_MAP: dict[str, list[str]] = {
    "port_scan": [
        "Закрой ненужные порты через firewall (iptables/ufw/nftables)",
        "Ограничь доступ к сервисным портам (22, 3389) по IP whitelist",
        "Замени Telnet (23) на SSH, RDP (3389) на VPN+RDP",
    ],
    "stealer_log": [
        "Принудительно сбрось пароли всех скомпрометированных аккаунтов",
        "Аннулируй все активные сессии (session tokens, cookies)",
        "Включи MFA для всех пользователей организации",
        "Проверь активные сессии через /events/{id}/reveal → cookie validator",
    ],
    "breach": [
        "Уведоми пользователей об утечке в соответствии с GDPR Art. 33 (72 часа)",
        "Сбрось скомпрометированные пароли",
        "Включи MFA",
        "Провести forensic анализ — как произошла утечка",
    ],
    "dark_web_mention": [
        "Мониторь тему на darknet форуме (поставить алерт)",
        "Проверь свежие логи доступа на аномалии",
        "Свяжись с threat intel командой для контекста",
    ],
    "ransomware_mention": [
        "КРИТИЧНО: активируй Incident Response план",
        "Изолируй потенциально скомпрометированные системы",
        "Сделай offline backup критичных данных",
        "Уведоми руководство и юридический отдел",
    ],
    "subdomain_takeover": [
        "Немедленно удали или обнови DNS запись для сиротского субдомена",
        "Аудит всех CNAME/A записей на наличие сиротских указателей",
        "Настрой мониторинг DNS изменений",
    ],
    "phishing_domain": [
        "Подай abuse жалобу на регистратора домена",
        "Добавь домен в Google Safe Browsing и Microsoft SmartScreen",
        "Оповести пользователей о фишинговом домене",
        "Запроси UDRP если домен нарушает trademark",
    ],
    "github_secret": [
        "НЕМЕДЛЕННО ротируй скомпрометированный секрет/ключ",
        "Удали секрет из git истории (git filter-repo)",
        "Включи GitHub Secret Scanning для предотвращения в будущем",
        "Аудит использования ключа в логах провайдера",
    ],
    "dns_misconfiguration": [
        "Добавь SPF запись: v=spf1 include:_spf.google.com ~all",
        "Настрой DKIM подпись для исходящей почты",
        "Включи DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com",
        "Добавь CAA запись для ограничения CA",
    ],
    "tls_issue": [
        "Обнови TLS до версии 1.2 минимум, рекомендуется 1.3",
        "Замени устаревшие cipher suites (RC4, DES, 3DES)",
        "Проверь срок действия сертификата, настрой auto-renewal (Let's Encrypt)",
    ],
    "s3_exposure": [
        "Немедленно закрой публичный доступ к bucket через AWS Console",
        "Аудит содержимого bucket — что было доступно",
        "Включи S3 Block Public Access на уровне аккаунта",
        "Включи CloudTrail для мониторинга доступа к S3",
    ],
    "nuclei_finding": [
        "Обнови уязвимый компонент до последней версии",
        "Примени патч вендора или WAF rule как временную меру",
        "Проведи penetration test для подтверждения эксплуатируемости",
    ],
    "forum_mention": [
        "Отслеживай тему и реагируй на легитимные жалобы",
        "Проверь содержимое на предмет утечки данных",
    ],
}

DEFAULT_HINTS = [
    "Изучи детали события в payload",
    "Оцени реальное влияние на бизнес",
    "Эскалируй в SOC если severity=critical/high",
]


def get_hints(event_type: str) -> list[str]:
    """Возвращает список рекомендаций для данного типа события."""
    return REMEDIATION_MAP.get(event_type, DEFAULT_HINTS)


def enrich_event_with_hints(event: dict) -> dict:
    """
    Добавляет поле remediation_hints к dict-представлению события.
    Не мутирует входной dict — возвращает новый.
    """
    hints = get_hints(event.get("event_type", ""))
    return {**event, "remediation_hints": hints}
