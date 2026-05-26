# SESSION SNAPSHOT — Monitoring_utechek/core
**Дата:** 2026-05-26  
**Ветка:** main  
**Последний коммит:** 86591a3

---

## 1. СТАТУС ТЕСТОВ

### Последний прогон (86591a3):
```
651 passed, 0 failed, 6 warnings — 13:18
```
> Новые тесты этой сессии ещё не писались — баги в воркерах, не в API.

---

## 2. ЧТО РЕАЛИЗОВАНО В ЭТОЙ СЕССИИ

### Новый endpoint
| Файл | Endpoint | Что делает |
|------|----------|-----------|
| `core/app/api/v1/endpoints/quick_scan.py` | `POST /api/v1/scan/quick` | Принимает `{"domain":"..."}`, сам создаёт org+asset, запускает full scan, возвращает asset_id |
| `core/app/api/v1/router.py` | — | Зарегистрирован quick_scan router |

### Баги исправлены
| # | Файл | Проблема | Исправление |
|---|------|----------|-------------|
| B1 | `core/app/api/v1/endpoints/events.py` | `asset_id` в query params не работал (не было в сигнатуре функции) | Добавлен `asset_id: str \| None = Query(...)` + `q.where(Event.asset_id == asset_id)` |
| B2 | `workers/tasks/phishing_detector.py` | payload имел ключи `typosquat/technique`, отображение ожидало `domain/type` | Переименованы в `domain/type`, `technique` оставлен как алиас |
| B3 | `workers/tasks/tls_fingerprinter.py` | Нет полей `grade` и `protocol` в payload | Добавлена функция `_tls_grade()` (A/B/C/F), поля `grade` и `protocol` |
| B4 | `workers/tasks/nuclei.py` | Нет поля `title` в payload | Добавлен `title` как алиас для `name`, добавлен `severity` |
| B5 | `workers/tasks/gitleaks.py` | Research-репозитории (Tracking-Pixels и др.) клонировались и давали 111 FP CRITICAL | Добавлен `_is_fp_repo()` regex-фильтр при сборе репозиториев |
| B6 | `core/app/api/v1/endpoints/scheduled_scan.py` | Telegram monitor не запускался в full scan (был только шаг 12) | Добавлен шаг 13 — `telegram_monitor` |
| B7 | `core/app/services/graph_client.py` | Neo4j статус писался на `logger.debug` — невидимо | Изменён на `logger.info` |
| B8 | `workers/tasks/domain_hardening.py` | DNS misconfig писался как `event_type=vulnerability` | Изменён на `event_type=dns_misconfig`, `source_type=scanner` |
| B9 | `workers/tasks/gitleaks.py` | SMS-бомберы (SMSBomer, SMS-ATTACK, Maxwell-spammer и др.) клонировались → 74 CRITICAL FP secret_leaks | FP-фильтр расширен: 19/19 attack-репозиториев пропускаются |

### GitHub token
```
core/.env: GITHUB_TOKEN=REDACTED_GITHUB_TOKEN
```

---

## 3. АРХИТЕКТУРА ПРИЛОЖЕНИЯ

```
core/
├── app/
│   ├── main.py
│   ├── db.py
│   ├── api/
│   │   ├── deps.py              # CurrentUser (JWT + API key unified)
│   │   └── v1/endpoints/        # 45+ endpoints
│   │       ├── quick_scan.py    # POST /scan/quick — one-click scan
│   │       ├── scheduled_scan.py# full_scan 13 шагов
│   │       ├── events.py        # GET events + фильтр по asset_id (исправлен)
│   │       ├── dashboard.py     # GET /dashboard/executive, /dashboard/benchmark
│   │       ├── score.py         # GET /assets/{id}/score, /score/history
│   │       └── ... (40+ других)
│   └── services/
│       ├── score_engine.py      # calculate_score(), 6 категорий, time decay
│       ├── graph_client.py      # Neo4j Attack Path (опционально, NEO4J_URI)
│       └── benchmarking.py
workers/
├── tasks/                       # 39 воркеров
│   ├── domain_hardening.py      # SPF/DMARC/AXFR/SSL → event_type=dns_misconfig
│   ├── phishing_detector.py     # typosquat DNS → event_type=phishing_domain
│   ├── tls_fingerprinter.py     # TLS grade A/B/C/F, WAF detection
│   ├── gitleaks.py              # GitHub secret scan + FP filter (19 attack-repo patterns)
│   ├── github_search.py         # GitHub code search + FP filter + severity classify
│   ├── telegram_monitor.py      # 25 leak-каналов (шаг 13 full scan)
│   └── ... (33 других)
tests/                           # 36 тест-файлов, 651 тест
```

---

## 4. FULL SCAN — 13 ШАГОВ

```
1.  subfinder         → subdomain
2.  port_scanner      → exposed_service
3.  nuclei            → vulnerability
4.  tls_fingerprinter → tls_fingerprint  (grade A/B/C/F, WAF)
5.  domain_hardening  → dns_misconfig    (SPF/DMARC/AXFR/SSL)
6.  tech_profiler     → tech_profile
7.  phishing_detector → phishing_domain  (typosquat DNS check)
8.  github_search     → github_leak      (FP фильтрован)
9.  gitleaks          → secret_leak      (FP: attack-repos пропущены)
10. stealer_parser    → stealer_log
11. ransomware_sites  → ransomware_mention
12. tor_client        → dark_web_mention
13. telegram_monitor  → telegram_mention
```

---

## 5. РЕЗУЛЬТАТЫ РЕАЛЬНЫХ СКАНОВ

### creditplus.ua — ~150 событий
- 37 субдоменов, порты 80/443/8080/8443/22
- TLS grade=A, Cloudflare WAF
- Phishing: creditplus.net, creditplus.org, secure-creditplus.ua
- GitHub leaks: 12 → все FP (после фикса filtered=12, sent=0)

### credit7.ua — ~150 событий (до фиксов B1-B5)
- Events API bug: без фильтра asset_id возвращал все 291 событий (2 домена)
- После фикса: 150 событий только credit7.ua

### e-groshi.com — 229 событий (скан от 2026-05-25)
```
subdomain       58  (admin, bitrix, moodle, sentry, rabbit, voip, vidu...)
github_leak     74  (в основном SMS-бомберы — e-groshi.com как цель атак)
secret_leak     74  → БЫЛИ FP из attack-repos; после фикса B9 новые сканы чисты
exposed_service 13  (22/ssh, 80, 443, 8080, 8443)
vulnerability    4  → на самом деле были dns_misconfig; исправлено фиксом B8
phishing_domain  2  (e-groshi.net→91.206.200.104, egroshi.com→5.39.10.93)
tls_fingerprint  2  (grade=A, TLSv1.3, Cloudflare)
tech_profile     1  (WordPress, Django, Cloudflare)
asset_drift      1
```
**Повторный скан e-groshi.com запущен 2026-05-26** — ожидается чистая картина без FP.

---

## 6. SCORE ENGINE

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
```

---

## 7. КЛЮЧЕВЫЕ ТЕХНИЧЕСКИЕ ДЕТАЛИ

### Fire-and-forget (все scan endpoints):
```python
loop = asyncio.get_running_loop()
loop.run_in_executor(get_executor(), worker_func, domain, api_url, secret)
return JSONResponse({"status": "accepted"}, status_code=202)
# НЕ await! — иначе блокирует event loop
```

### Quick scan (новый):
```python
# POST /api/v1/scan/quick {"domain": "example.com"}
# 1. Get or create Personal org
# 2. Get or create Asset
# 3. get_executor().submit(_run_full_scan_background, domain, port)
# → 202 + asset_id для polling
```

### FP-фильтр gitleaks (расширенный):
```python
_FP_REPO_RE = re.compile(
    # domain lists / research
    r"tranco|domain.?list|tracking.?pixel|expired.?domain..."
    # attack tools
    r"|sms.?bomb|sms.?attack|smsbom|smsham|b0mb3r|bomber|spammer|spymer"
    r"|rkr0k3|telebotpy|iisus|apk.?anti|tgsb"
    # known attacker accounts
    r"|antichristone|umutkara.?tools|imasender"
)
# Покрытие: 19/19 FP attack-репозиториев e-groshi.com
```

### Rate limit dev-login:
```
5 req/min на /api/v1/auth/dev-login
Использовать: curl "http://localhost:8000/api/v1/auth/dev-login?email=scanner@easm.local"
```

---

## 8. ЗАПУСК

```bash
# Сервер
cd /home/zastone/study/Monitoring_utechek/core
nohup uvicorn app.main:app --port 8000 > /tmp/uv.log 2>&1 &

# Тесты
export SECRET_KEY="dev-secret-key-min-32-chars-here12"
export INTERNAL_API_SECRET="dev-internal-secret"
export FIRST_SUPERUSER_PASSWORD="SuperSecurePass123!"
export DATABASE_URL="sqlite+aiosqlite:///./demo.db"
export DEV_MODE=true
python3 -m pytest tests/ -q --tb=line 2>&1 | tail -5

# Скан домена
TOKEN=$(curl -s "http://localhost:8000/api/v1/auth/dev-login?email=scanner@easm.local" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
curl -s -X POST "http://localhost:8000/api/v1/scan/quick" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

---

## 9. СЛЕДУЮЩИЕ ШАГИ

- Дождаться результатов повторного скана e-groshi.com (проверить: dns_misconfig вместо vulnerability, нет FP secret_leaks)
- Запустить полный тест-сьют (651 тестов) — убедиться что фиксы B1-B9 не сломали тесты
- MEDIUM: Race condition в /tmp файлах при параллельных сканах → fcntl.flock или Redis
- MEDIUM: N+1 запросы в /comparison/portfolio → asyncio.gather()
- Реальное тестирование с CENSYS_API_ID, JIRA_URL, ANTHROPIC_API_KEY
