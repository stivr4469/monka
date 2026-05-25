## Анализ: что реализовано vs. что описано

### Покрытие описанных требований: ~65%

**Что уже есть и работает ✅**

| Требование | Реализация |
|---|---|
| Attack surface (nmap, порты) | `port_scanner.py` — nmap |
| Subdomains discovery | `subfinder.py` + crt.sh |
| Technologies | `tech_profiler.py` — заголовки, куки, сигнатуры |
| Services / vulns | `nuclei.py` |
| Shodan enrichment | `shodan_enricher.py` |
| Dark web monitoring | `darknet_monitor.py` — ahmia, ransomwatch, darksearch |
| Ransomware leak sites | `ransomware_sites.py` — Tor + Playwright (LockBit3, Medusa, Clop, RansomEXX, Rhysida и др.) |
| Telegram scraping | `telegram_monitor.py` + `stealer_tg_channels.py` (Telethon/MTProto) |
| Stealer log parsing | `stealer_parser.py` — Redline/Vidar/Raccoon форматы |
| Stealer sources | `stealer_sources.py` — Hudson Rock, Snusbase, LeakCheck |
| IntelX integration | `intelx_api.py` |
| Email breach check | `breach_checker.py` — HIBP + LeakCheck |
| GitHub secret leaks | `gitleaks.py` |
| GitHub mentions | `github_search.py` |
| Phishing/typosquatting | `phishing_detector.py` |
| Subdomain takeover | `takeover_detector.py` |
| S3 open buckets | `s3_scanner.py` |
| TLS fingerprinting | `tls_fingerprinter.py` — JA4 |
| Cookie validity check | `cookie_validator.py` |
| Domain hardening | `domain_hardening.py` — SPF/DKIM/DMARC/CAA/HSTS |
| Human OSINT | `human_osint.py` |
| Multi-tenant MSSP | модели + endpoints |
| Scheduled monitoring | `scan_schedules` + Celery |
| Alerts (Telegram) | `telegram_alerts.py` — rule-based |
| Attack path graph | Neo4j endpoints |
| PDF reports | executive + technical |
| API keys (SIEM) | `api_keys` model + SHA-256 |

**Что отсутствует ❌**

| Gap | Важность |
|---|---|
| **Security Score / Rating** (как у SecurityScorecard) | КРИТИЧНО |
| **Censys** integration | высокая |
| **masscan** (быстрое сканировани�� /24 за секунды) | высокая |
| **WHOIS / registrant monitoring** (смена владельца домена) | высокая |
| **BGP/ASN monitoring** (смена IP-диапазонов) | средняя |
| **Brand monitoring clearnet** (логотип/название в соц.сетях, форумах) | высокая |
| **Supply chain / third-party domains** | высокая |
| **Mobile app scanning** (APKs, App Store) | средняя |
| **Executive Dashboard** с трендами и скором | КРИТИЧНО |
| **Automated remediation suggestions** | средняя |
| **VirusTotal / MalwareBazaar** integration | средняя |
| **Continuous asset discovery** (OSINT по компании через ASN, registrant) | высокая |

---

## BRD — Attack Surface & Brand Protection Platform

### Аналоги на рынке

| Продукт | Фокус | Цена | Слабые места |
|---|---|---|---|
| **SecurityScorecard** | Security rating, vendor risk | $15k–$100k/год | Нет dark web, нет stealer logs |
| **Recorded Future** | Threat intel, dark web | $50k–$500k/год | Слишком дорого для SMB |
| **Digital Shadows (ReliaQuest)** | Brand + dark web | $30k–$150k/год | Нет ASM, сложный UX |
| **CrowdStrike Falcon Surface** | ASM only | $20k+/год | Нет dark web мониторинга |
| **Cyberpion** | ASM + supply chain | $15k–$80k/год | Нет stealer/telegram |
| **Flare.io** | Dark web + stealer logs | $5k–$30k/год | Нет ASM |
| **SpyCloud** | Stealer logs only | $10k–$50k/год | Только credentials |
| **Intezer / Pulsedive** | IOC intel | $2k–$15k/год | Нет мониторинга |

**Наша ниша:** единственная платформа где ASM + stealer logs + dark web + ransomware + Telegram — всё в одном, с русскоязычным рынком как точкой входа, и ценой в 5–10× ниже западных аналогов.

---

## BRD: "SURFACE" — Attack Surface & Dark Web Intelligence Platform

### Концепция продукта

**Точка входа: доменное имя.** Дальше — полная автоматизированная разведка.

```
domain.com
    │
    ├── RECON LAYER
    │   ├── Subdomains (subfinder, crt.sh, bruteforce)
    │   ├── IPs & ASN / BGP prefixes
    │   ├── WHOIS history & registrant graph
    │   ├── Certificate transparency (crt.sh real-time)
    │   └── Shodan / Censys / FOFA asset fingerprint
    │
    ├── ATTACK SURFACE LAYER
    │   ├── Port scan (nmap + masscan для /24)
    │   ├── Service fingerprint (banners, versions)
    │   ├── Technology profiling (заголовки, JS libs, CMS, CDN)
    │   ├── Vulnerability scan (nuclei templates)
    │   ├── TLS/JA4 fingerprinting
    │   ├── Misconfigurations (S3, open dirs, .git/.env exposure)
    │   ├── Subdomain takeover detection
    │   └── Domain hardening score (SPF/DKIM/DMARC/CAA/HSTS/MTA-STS)
    │
    ├── CREDENTIAL & LEAK LAYER
    │   ├── Email breach (HIBP, LeakCheck, DeHashed)
    │   ├── Stealer logs (Telegram channels, markets, darknet drops)
    │   │   ├── Cookie validity (активные сессии → RCE-level risk)
    │   │   └── Password hashes → plaintext recovery pipeline
    │   ├── GitHub secret leaks (gitleaks + GitHub Search API)
    │   ├── Paste monitoring (Pastebin, Ghostbin, rentry.co)
    │   └── IntelX phonebook search
    │
    ├── DARK WEB LAYER
    │   ├── Ransomware leak sites (Tor, 20+ группировок)
    │   ├── Darknet forums (ahmia, darksearch, специфические форумы)
    │   ├── Telegram: stealer каналы + хакерские форумы
    │   │   └── собственный парсер + MTProto (Telethon)
    │   └── Human OSINT (профили сотрудников �� spear phishing risk)
    │
    ├── BRAND SAFETY LAYER  ← НОВЫЙ, нужно реализовать
    │   ├── Phishing/typosquatting domains (real-time CT + DNS)
    │   ├── Brand mentions: Reddit, Twitter/X, форумы
    │   ├── Logo detection (reverse image search pipeline)
    │   ├── Mobile apps: App Store + Google Play мониторинг
    │   └── Supply chain: мониторин�� доменов партнёров/вендоров
    │
    └── INTELLIGENCE OUTPUT
        ├── Security Score (0–100, weighted по severity + asset importance)
        ├── Risk Trends (история score по дням/неделям)
        ├── Executive PDF (non-technical, для C-suite)
        ├── Technical PDF (детальный, для SOC)
        ├── Alerts (Telegram, Slack, Email, Webhook)
        ├── SIEM export (JSON/STIX/CEF via API key)
        └── Attack Path Graph (Neo4j — путь от утечки до RCE)
```

---

### Security Score Engine (главная недостающая фича)

**Модель оценки (0–100, как у SecurityScorecard):**

```python
# Категории и веса
SCORE_CATEGORIES = {
    "network_security":     0.20,  # открытые порты, CVE, service versions
    "dns_health":           0.10,  # SPF, DKIM, DMARC, CAA
    "application_security": 0.15,  # tech stack EOL, TLS version, headers
    "credential_exposure":  0.25,  # stealer logs, breaches, GitHub secrets
    "dark_web_presence":    0.20,  # ransomware, darknet mentions, paste leaks
    "brand_safety":         0.10,  # phishing domains, typosquatting, app spoofs
}

# Расчёт: начинаем с 100, вычитаем штрафы
# critical event → -15 очков
# high event     → -8 очков
# medium event   → -3 очка
# low event      → -1 очко
# + поправочный коэффициент на asset_importance (0.1–2.0)
```

**Сравнение с конкурент��ми + своя метрика:**
```
SecurityScorecard: A/B/C/D/F (письмо)
Наш:               0–100 + отдельный score по 6 категориям
```

---

### Roadmap по приоритетам

**Фаза 1 (1–2 мес.) — Закрыть критические gaps:**
1. Security Score Engine — weighted scoring по существующим событиям
2. Executive Dashboard — score trend, top risks, category breakdown
3. masscan интеграция — быстрое сканирование IP-диапазонов
4. WHOIS monitoring — детекция смены регистранта/NS

**Фаза 2 (2–4 мес.) — Brand Safety:**
1. Real-time CT мониторинг (stream с crt.sh) → автодетекция похожих доменов
2. Telegram brand mentions (расширение telegram_monitor для brand keywords)
3. Supply chain — добавление доменов партнёров как secondary assets
4. Mobile app monitoring (App Store/Google Play scraping)

**Фаза 3 (4–6 мес.) — Enterprise:**
1. Censys интеграция
2. STIX/TAXII export для SIEM
3. Multi-org comparison (benchmark против отрасли)
4. Automated remediation playbooks (Jira/ServiceNow tickets)
5. AI-driven risk narrative (LLM summary для executive)

---

### Тарифы (захватить рынок SMB → Enterprise)

| План | Цена | Домены | Что входит |
|---|---|---|---|
| **Starter** | $299/мес | 3 | Score + basic ASM + breach check |
| **Professional** | $999/мес | 15 | Всё + dark web + stealer logs + Telegram |
| **Enterprise** | $3,500/мес | 100 | Всё + MSSP + SIEM + SLA 99.9% |
| **MSSP** | договорная | безлимит | White-label + reseller margin |

*SecurityScorecard берёт $15k–$100k/год за меньший функционал.*

---

### Итоговая оценка покрытия

**Текущий код покрывает ~65% BRD.** Реализованы все технические слои (ASM, credentials, dark web, Telegram). Главные пробелы — **Security Score** (без него продукт не продашь B2B), **Brand Safety clearnet**, и **Executive Dashboard**.

Из аналогов ближайший конкур��нт по функционалу — **Flare.io** (~$15k/год), но у нас есть ASM которого у них нет. Если добавить Score Engine + Dashboard — это полноценная замена связки **Flare.io + SecurityScorecard** за треть цены.
