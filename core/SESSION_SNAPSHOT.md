# SESSION SNAPSHOT — Monitoring_utechek/core
**Дата:** 2026-05-25  
**Ветка:** main  
**Последний коммит:** 30f029c

---

## 1. СТАТУС ТЕСТОВ

### Финальный прогон (30f029c):
```
651 passed, 0 failed, 6 warnings — 13:18
```

### История сессии:
```
Начало сессии: 320 passed (0 failed)  — база
После фаз 11-13: 455 passed
После BGP/Mobile/Remediation: 583 passed
После Ticketing/Comparison/Benchmarking: 623 passed
После code review fixes: 651 passed ✅
```

---

## 2. ЧТО РЕАЛИЗОВАНО В ЭТОЙ СЕССИИ (фазы 11–13)

### Phase 11 — Security Score + Dashboard
| Задача | Файл | Статус |
|--------|------|--------|
| 11.A+B Score Engine | `core/app/services/score_engine.py` | ✅ |
| 11.C Executive Dashboard | `core/app/api/v1/endpoints/dashboard.py` | ✅ |
| 11.D Remediation Hints | `workers/tasks/remediation_hints.py` | ✅ |

### Phase 12 — Brand Safety
| Задача | Файл | Статус |
|--------|------|--------|
| 12.A CT Monitor | `workers/tasks/ct_monitor.py` | ✅ |
| 12.B+E Brand Monitor | `workers/tasks/brand_monitor.py` | ✅ |
| 12.C Supply Chain | Asset.asset_type + parent_asset_id | ✅ |
| 12.D Mobile App Monitor | `workers/tasks/mobile_monitor.py` | ✅ |

### Phase 13 — Enterprise
| Задача | Файл | Статус |
|--------|------|--------|
| 13.A masscan | `workers/tasks/masscan_scanner.py` | ✅ |
| 13.B Censys | `workers/tasks/censys_enricher.py` | ✅ |
| 13.C WHOIS Monitor | `workers/tasks/whois_monitor.py` | ✅ |
| 13.D BGP/ASN Monitor | `workers/tasks/bgp_monitor.py` | ✅ |
| 13.E STIX 2.1 Export | `workers/tasks/stix_export.py` | ✅ |
| 13.F Industry Benchmarking | `core/app/services/benchmarking.py` | ✅ |
| 13.G AI Risk Narrative | `workers/tasks/ai_narrative.py` | ✅ |
| 13.H Jira/ServiceNow Tickets | `workers/tasks/ticketing.py` | ✅ |
| 13.I Multi-org Comparison | `core/app/api/v1/endpoints/comparison.py` | ✅ |

---

## 3. АРХИТЕКТУРА ПРИЛОЖЕНИЯ

```
core/
├── app/
│   ├── main.py
│   ├── db.py
│   ├── api/
│   │   ├── deps.py              # CurrentUser (JWT + API key unified)
│   │   └── v1/endpoints/        # 44 endpoints
│   │       ├── dashboard.py     # GET /dashboard/executive, /dashboard/benchmark
│   │       ├── score.py         # GET /assets/{id}/score, /score/history
│   │       ├── comparison.py    # GET /comparison/orgs, /comparison/portfolio
│   │       ├── stix_export.py   # GET /export/stix
│   │       ├── ai_narrative.py  # POST /ai/narrative
│   │       ├── tickets.py       # POST/GET /events/{id}/ticket
│   │       ├── events.py        # GET events + PATCH resolve + GET hints
│   │       ├── whois_scan.py    # POST /scan/whois
│   │       ├── ct_scan.py       # POST /scan/ct
│   │       ├── masscan_scan.py  # POST /scan/masscan (Enterprise only)
│   │       ├── brand_scan.py    # POST /scan/brand
│   │       ├── censys_scan.py   # POST /scan/censys
│   │       ├── bgp_scan.py      # POST /scan/bgp
│   │       ├── mobile_scan.py   # POST /scan/mobile
│   │       └── ... (30+ других)
│   ├── services/
│   │   ├── score_engine.py      # calculate_score(), 6 категорий, time decay
│   │   └── benchmarking.py      # compare_with_benchmark(), 8 отраслей
│   └── models/
│       ├── event.py             # resolved, resolved_by, ticket_ref поля добавлены
│       ├── asset.py             # asset_type, parent_asset_id поля добавлены
│       ├── organization.py      # industry поле добавлено
│       └── score_snapshot.py    # новая модель
workers/
├── tasks/                       # 39 воркеров
│   ├── score_engine.py
│   ├── whois_monitor.py         # RDAP, baseline comparison
│   ├── ct_monitor.py            # crt.sh + Levenshtein
│   ├── masscan_scanner.py       # masscan + nmap -sV
│   ├── brand_monitor.py         # Reddit + HN + Telegram
│   ├── censys_enricher.py       # Censys Search API
│   ├── bgp_monitor.py           # BGPView API
│   ├── mobile_monitor.py        # iTunes + Google Play
│   ├── ai_narrative.py          # Claude API + static fallback
│   ├── stix_export.py           # STIX 2.1 без зависимостей
│   ├── ticketing.py             # Jira REST + ServiceNow REST
│   ├── remediation_hints.py     # 14 типов событий → actionable советы
│   └── ... (27 других)
tests/                           # 36 тест-файлов, 651 тест
```

---

## 4. SCORE ENGINE

```python
SCORE_CATEGORIES = {
    "network_security":     0.20,  # порты, CVE, сервисы
    "dns_health":           0.10,  # SPF/DKIM/DMARC/CAA
    "application_security": 0.15,  # TLS, headers, tech EOL
    "credential_exposure":  0.25,  # stealer logs, breaches
    "dark_web_presence":    0.20,  # ransomware, darknet, pastes
    "brand_safety":         0.10,  # phishing, typosquatting
}
# Penalties: critical=-25, high=-10, medium=-4, low=-1
# Time decay: T(t) = e^(-0.003 × Δt_days)
# Endpoints: GET /assets/{id}/score, /organizations/{id}/score, /assets/{id}/score/history
```

---

## 5. КЛЮЧЕВЫЕ ТЕХНИЧЕСКИЕ ДЕТАЛИ

### Fire-and-forget паттерн (все scan endpoints):
```python
loop = asyncio.get_running_loop()
loop.run_in_executor(get_executor(), worker_func, domain, api_url, secret)
return JSONResponse({"status": "accepted"}, status_code=202)
# НЕ await! — иначе блокирует event loop
```

### Дедупликация воркеров:
```python
# /tmp/brand_seen_{safe_domain}.json  — limit 5000
# /tmp/mobile_seen_{safe_domain}.json — limit 5000
# /tmp/ct_seen_{safe_domain}.json     — limit 1000 (ct_monitor)
# /tmp/bgp_baseline_{safe_domain}.json
# /tmp/whois_baseline_{safe_domain}.json
```

### STIX 2.1 маппинг:
```
stealer_log / breach        → indicator (malicious-activity)
port_scan                   → observed-data (network-traffic)
nuclei_finding              → vulnerability (CVE если есть)
dark_web_mention            → threat-actor
ransomware_mention          → threat-actor
остальные                   → observed-data (generic)
```

### AI Narrative:
```python
# Claude Haiku с prompt caching (ephemeral на system prompt)
# Fallback при отсутствии ANTHROPIC_API_KEY → static template
# Grades: A(90+) B(75+) C(60+) D(45+) F(<45)
```

### Ticketing:
```python
# Jira REST API v3: POST /rest/api/3/issue (Basic Auth)
# ServiceNow: POST /api/now/table/incident (Basic Auth)
# Приоритет: Jira → ServiceNow fallback
# ticket_ref формат: "jira:SEC-123" / "servicenow:INC0001234"
```

### Industry Benchmarking:
```python
# 8 отраслей: fintech/healthcare/ecommerce/saas/telecom/manufacturing/media/other
# Live данные из ScoreSnapshot (≥5 org в отрасли), иначе статика
# rank: below_average / average / above_average / top_quartile
# GET /dashboard/benchmark
```

---

## 6. CODE REVIEW FIXES (применены)

| # | Severity | Проблема | Исправлени�� |
|---|----------|----------|-------------|
| 1 | CRITICAL | parents[6] → неверный путь к workers | parents[5] в stix_export.py, ai_narrative.py |
| 2 | CRITICAL | await run_in_executor блокирует event loop | убран await в whois_scan.py, bgp_scan.py |
| 3 | HIGH | get_event_loop() deprecated Python 3.12 | → get_running_loop() в censys_scan.py |
| 4 | HIGH | Silent except без лога | logger.warning в benchmarking.py |
| 5 | HIGH | org_name=UUID в AI narrative | загружаем org.name из БД |
| 6 | HIGH | Неограниченный рост /tmp кэш-файлов | _MAX_SEEN_URLS=5000 в brand/mobile monitor |

---

## 7. ПОЛЕЗНЫЕ КОМАНДЫ

```bash
# Запуск тестов
cd /home/zastone/study/Monitoring_utechek/core
export SECRET_KEY="dev-secret-key-min-32-chars-here12"
export INTERNAL_API_SECRET="dev-internal-secret"
export FIRST_SUPERUSER_PASSWORD="SuperSecurePass123!"
export DATABASE_URL="sqlite+aiosqlite:///./demo.db"
export DEV_MODE=true
python3 -m pytest tests/ -q --tb=line 2>&1 | tail -5

# Только новые тесты фаз 11-13
python3 -m pytest tests/test_score_engine.py tests/test_dashboard.py tests/test_benchmarking.py \
  tests/test_whois_monitor.py tests/test_ct_monitor.py tests/test_masscan_scanner.py \
  tests/test_brand_monitor.py tests/test_censys_enricher.py tests/test_bgp_monitor.py \
  tests/test_mobile_monitor.py tests/test_ai_narrative.py tests/test_stix_export.py \
  tests/test_ticketing.py tests/test_comparison.py tests/test_remediation.py \
  tests/test_supply_chain.py -q

# Запуск приложения
uvicorn app.main:app --reload --port 8000
```

---

## 8. СЛЕДУЮЩИЕ ШАГИ (если продолжать)

- MEDIUM: Race condition в /tmp файлах при параллельных сканах → fcntl.flock или Redis
- MEDIUM: N+1 запросы в /comparison/portfolio → asyncio.gather()
- MEDIUM: Вынести validate_domain и _safe_domain_filename в core/app/utils/
- Phase 12.F / 13.J: Senior code review по всему добавленному коду (можно запустить python-reviewer агент)
- Реальное тестирование: запуск с настоящими CENSYS_API_ID, JIRA_URL, ANTHROPIC_API_KEY
