# EASM Platform — Полное описание модулей

Платформа состоит из двух сервисов:
- **core/** — FastAPI REST API (Control Plane): авторизация, хранение данных, бизнес-логика, веб-интерфейс
- **workers/** — Celery задачи (Data Plane): сканирование, парсинг, OSINT, мониторинг

---

## CORE — FastAPI приложение

### Точка входа

**`core/app/main.py`**
Инициализация FastAPI-приложения. При старте:
- Проверяет что секреты не оставлены дефолтными (SECRET_KEY, INTERNAL_API_SECRET)
- Создаёт таблицы БД через SQLAlchemy (dev-режим) или Alembic (production)
- Создаёт суперпользователя и дефолтную организацию если их нет
- Инициализирует индексы OpenSearch (easm-events, easm-leaked-credentials) и ILM-политику
- Инициализирует constraints в Neo4j
- Подключает CORS, rate-limit middleware, структурированное логирование
- Монтирует статический SPA-дашборд на `/`

---

### Инфраструктура

**`core/app/core/config.py`**
Pydantic Settings — все переменные окружения. Читает `.env` файл.
Содержит функцию `validate_secrets()` — блокирует старт если SECRET_KEY или INTERNAL_API_SECRET
оставлены дефолтными значениями. DEV_MODE=True активирует dev-login эндпоинт.

**`core/app/core/security.py`**
JWT-токены: генерация (`create_access_token`), верификация (`decode_token`).
Хеширование паролей через bcrypt (`hash_password`, `verify_password`).
Алгоритм: HS256, TTL токена берётся из настроек.

**`core/app/core/crypto.py`**
AES-шифрование паролей из стилер-логов через Fernet (AES-128-CBC + HMAC-SHA256).
Ключ выводится из `INTERNAL_API_SECRET` через SHA-256 → urlsafe-base64.
Функции: `encrypt_password(password, secret)`, `decrypt_password(token, secret)`.
Один ключ используется и в workers и в core — без отдельной настройки.

**`core/app/core/rate_limit.py`**
Rate limiting через slowapi. При наличии REDIS_URL использует RedisStorage
(корректно работает при нескольких репликах). Fallback на MemoryStorage если Redis недоступен.

**`core/app/db.py`**
Настройка SQLAlchemy async engine + session factory.
Функция `get_db()` — dependency для FastAPI, используется через `DBDep = Annotated[AsyncSession, Depends(get_db)]`.

**`core/app/api/deps.py`**
FastAPI dependencies: `CurrentUser` — проверяет JWT из заголовка Authorization.
Также поддерживает аутентификацию через API-ключи (Bearer easm_*):
при получении токена с префиксом `easm_` ищет по SHA-256 хешу в таблице api_keys,
проверяет is_active и expires_at, обновляет last_used_at.
`verify_internal_secret` — проверяет токен воркеров (INTERNAL_API_SECRET).

**`core/app/workers_client.py`**
Синглтон ThreadPoolExecutor для синхронных задач (report_generator, cookie_validator).
`ensure_workers_path()` — добавляет папку workers/ в sys.path чтобы core мог импортировать task-модули напрямую.

**`core/app/middleware/logging_middleware.py`**
Структурированное логирование каждого HTTP-запроса: метод, путь, статус, время выполнения,
X-Request-ID для трассировки.

**`core/alembic/env.py`**
Конфигурация Alembic для async SQLAlchemy. Берёт DATABASE_URL из settings,
импортирует все модели для autogenerate. Цепочка миграций:
add_org_plan → add_mssp_fields → add_event_condition → add_audit_log → add_api_keys → add_notifications.

---

### Модели данных (SQLAlchemy ORM)

**`core/app/models/organization.py`**
Организация-тенант. Поля: id, name, slug, plan (starter/professional/enterprise),
webhook_url (для critical-событий), mssp_parent_id (иерархия MSSP).
Enum OrgPlan определяет доступные фичи по тарифу.

**`core/app/models/user.py`**
Пользователь. Поля: id, email, hashed_password, is_superuser, is_active, organization_id.
Relationship к Organization.

**`core/app/models/asset.py`**
Контролируемый актив (домен). Поля: id, domain, description, is_active, organization_id,
risk_score (0-100), importance (0.5/1.0/2.0 — влияет на вес в формуле риска).
Relationship к событиям.

**`core/app/models/event.py`**
Нормализованное событие безопасности от воркера. Поля: id, event_type, severity
(info/low/medium/high/critical), source_type, source_name, target_domain, payload (JSON),
detected_at, dedup_hash (64-char SHA для дедупликации), asset_id,
condition (текст: что нужно сделать для устранения), resolved_at (когда устранено).

**`core/app/models/alert_rule.py`**
Правило Telegram-алерта. Поля: id, organization_id, chat_id, min_severity,
event_types (JSON-список), is_active. Правило срабатывает когда event_type
входит в список и severity >= min_severity.

**`core/app/models/scan_schedule.py`**
Расписание автоматического сканирования для домена. Поля: id, asset_id, frequency
(daily/weekly/hourly), last_run, next_run, is_active.

**`core/app/models/api_key.py`**
API-ключ для SIEM/SOAR интеграции. Поля: id, user_id, name, key_hash (SHA-256),
permissions (JSON), created_at, last_used_at, expires_at, is_active.
Raw key никогда не хранится — только хеш.

**`core/app/models/audit_log.py`**
Журнал аудита расшифровок паролей. Поля: id, user_id, action ("reveal_password"),
target_id (event_id), ip_address, user_agent, created_at.
Каждое обращение к endpoint /reveal фиксируется здесь.

**`core/app/models/notification.py`**
Уведомление для организации. Поля: id, org_id, event_id (опционально), message,
severity, is_read, created_at. Создаётся автоматически при ingest critical-событий.

---

### Схемы (Pydantic)

**`core/app/schemas/normalized_event.py`**
Схема входящего события от воркера: `NormalizedEvent` (одиночный ingest),
`BulkIngestRequest` (батч до N событий). Валидация полей, enum severity.
Поле `condition` — опциональная подсказка по устранению (если не передана — генерируется автоматически).

**`core/app/schemas/asset.py`**
AssetCreate, AssetRead, RiskScoreResponse (с breakdown по событиям).
`RiskEventItem` содержит: event_id, event_type, severity, contribution (float),
detected_at, condition — детализация для UI breakdown-панели.

**`core/app/schemas/alert_rule.py`**
AlertRuleCreate / AlertRuleRead / AlertRuleUpdate для CRUD правил алертов.

**`core/app/schemas/user.py`**
UserCreate, UserRead, Token (access_token + token_type).

---

### API Endpoints

**`core/app/api/v1/endpoints/auth.py`**
- `POST /auth/token` — логин по email/password, возвращает JWT (rate limit 10/min)
- `POST /auth/register` — регистрация нового пользователя
- `GET /auth/me` — профиль текущего пользователя
- `GET /auth/dev-login` — быстрый вход без пароля (только DEV_MODE=True, в production → 404)

**`core/app/api/v1/endpoints/assets.py`**
CRUD активов + вся бизнес-логика риска:
- `POST /assets/` — добавить домен под мониторинг
- `GET /assets/` — список активов организации
- `GET /assets/{id}` — детали актива
- `PATCH /assets/{id}` — обновление (importance, description)
- `DELETE /assets/{id}` — деактивация (soft-delete)
- `GET /assets/{id}/risk-score` — Risk Score 0-100 с breakdown по событиям
  Формула: `S = max(0, 100 − Σ W(sev) × exp(-λ×days) × importance)`, λ=0.003
  Веса: critical=25, high=13.5, medium=8, low=3. Breakdown сортируется по contribution DESC.
- `GET /assets/{id}/report/technical` — PDF технический отчёт (rate limit 5/min)
- `GET /assets/{id}/report/executive` — PDF executive-summary (rate limit 5/min)
- `GET /assets/{id}/map` — дерево инфраструктуры (поддомены → IP → порты → технологии)

**`core/app/api/v1/endpoints/events.py`**
- `GET /events/` — список событий с фильтрами (severity, event_type, domain, asset_id, date_from/to)
- `GET /events/{id}` — детали события
- `GET /events/export` — экспорт в CSV с теми же фильтрами (StreamingResponse)

**`core/app/api/v1/endpoints/ingest.py`**
Внутренний эндпоинт (только для воркеров, требует INTERNAL_API_SECRET):
- `POST /internal/ingest` — принять одно нормализованное событие.
  Дедупликация по dedup_hash. Автогенерация condition если не передан.
  Асинхронно: дублирует в OpenSearch, обновляет Neo4j граф, отправляет Telegram-алерт,
  вызывает webhook для critical-событий, создаёт Notification.
- `POST /internal/ingest/bulk` — батч-приём: один SELECT IN для дедупликации,
  один db.add_all() для вставки, асинхронная индексация каждого события.

**`core/app/api/v1/endpoints/alerts.py`**
CRUD правил Telegram-алертов (настраиваются на организацию):
- `POST /alerts/` — создать правило (chat_id, min_severity, event_types)
- `GET /alerts/` — список правил организации
- `PATCH /alerts/{id}` — обновить (включить/выключить, изменить фильтры)
- `DELETE /alerts/{id}` — удалить правило
- `POST /alerts/test/{id}` — отправить тестовый алерт в Telegram немедленно

**`core/app/api/v1/endpoints/internal_alerts.py`**
Внутренний эндпоинт для воркеров:
- `GET /internal/alert-rules` — возвращает активные правила алертов организации
  (без JWT, с INTERNAL_API_SECRET). Используется воркером telegram_alerts
  чтобы знать куда слать уведомления.

**`core/app/api/v1/endpoints/github_scan.py`**
- `POST /scan/github` — запустить поиск утечек API-ключей и секретов в GitHub
  для указанного домена/организации.

**`core/app/api/v1/endpoints/paste_scan.py`**
- `POST /scan/paste` — запустить мониторинг Pastebin, GitHub Gist и аналогичных
  paste-сервисов на предмет упоминаний домена или утечек.

**`core/app/api/v1/endpoints/telegram_scan.py`**
- `POST /scan/telegram` — запустить мониторинг Telegram-каналов стилеров
  на наличие данных указанного домена.

**`core/app/api/v1/endpoints/darknet_scan.py`**
- `POST /scan/darknet` — запустить мониторинг darknet через Tor + IntelX:
  ransomware-сайты, форумы, leak-базы.

**`core/app/api/v1/endpoints/hardening_scan.py`**
- `POST /scan/hardening` — проверка security hardening домена: HTTP-заголовки
  (CSP, HSTS, X-Frame-Options и др.), open redirect, информационные утечки сервера.

**`core/app/api/v1/endpoints/phishing_scan.py`**
- `POST /scan/phishing` — поиск фишинговых доменов имитирующих указанный домен:
  typosquatting, homoglyph-замена, doppelganger-домены.

**`core/app/api/v1/endpoints/port_scan.py`**
- `POST /scan/ports` — сканирование открытых портов через nmap/masscan.
  Создаёт события exposed_service для нестандартных открытых портов.

**`core/app/api/v1/endpoints/s3_scan.py`**
- `POST /scan/s3` — поиск публично доступных S3-бакетов ассоциированных с доменом.
  Проверяет типичные naming-паттерны: company-backup, company-assets и т.д.

**`core/app/api/v1/endpoints/cookie_scan.py`**
- `POST /scan/cookies` — проверка активности украденных сессионных кук из стилер-логов.
  Пассивная проверка через HEAD-запросы — не генерирует алертов на WAF/EDR жертвы.
  Живые сессии порождают события active_session_leak (critical).
  Читает ZIP-архив стилер-лога из /tmp.

**`core/app/api/v1/endpoints/takeover_scan.py`**
- `POST /scan/takeover` — детектирование захвата поддоменов (subdomain takeover):
  ищет CNAME-записи указывающие на удалённые/незарегистрированные сервисы
  (GitHub Pages, Heroku, S3 и др.).

**`core/app/api/v1/endpoints/tls_scan.py`**
- `POST /scan/tls` — анализ TLS-сертификата: срок истечения, JA4-fingerprint,
  слабые cipher suites, цепочка доверия, mismatch доменов.

**`core/app/api/v1/endpoints/enrich_scan.py`**
- `POST /scan/enrich` — обогащение данных об активе через Shodan API:
  исторические данные о портах, баннеры сервисов, геолокация, ASN.

**`core/app/api/v1/endpoints/breach_scan.py`** (доступен через `/breach`)
- `POST /breach/check` — проверка email/домена по базам утечек (HaveIBeenPwned API).

**`core/app/api/v1/endpoints/stealer.py`**
- `POST /stealer/upload` — загрузка ZIP-архива стилер-лога вручную.
  Запускает парсер stealer_parser в ThreadPool.
- `GET /stealer/logs` — список загруженных стилер-логов.

**`core/app/api/v1/endpoints/stealer_sources.py`**
- `POST /stealer/sources/run` — запустить автоматический сбор стилер-логов
  из настроенных Telegram-каналов стилеров (без ручной загрузки).

**`core/app/api/v1/endpoints/human_osint_scan.py`**
- `POST /scan/human-osint` — OSINT по сотрудникам компании:
  поиск публичных профилей на GitHub, LinkedIn (DDG Lite), корпоративных email-паттернов.
  Детектирует VIP-персон (C-level, security-команду).
  Результат: список сотрудников с профилями, должностями, публичными ссылками.

**`core/app/api/v1/endpoints/tech_scan.py`**
- `POST /scan/tech-profile` — Wappalyzer-like детектирование технологий:
  анализ HTTP-заголовков, кук, тела страницы. 35 сигнатур технологий.
  EOL-проверка версий (PHP 7.x, Nginx <1.22, IIS <8.5 и др.).
  Возвращает список технологий с версиями и флагом EOL.

**`core/app/api/v1/endpoints/reveal.py`**
- `GET /events/{id}/reveal` — расшифровка пароля из стилер-события.
  Только для source_type in (stealer, stealer_log, breach).
  Только для плана Professional/Enterprise или superuser.
  Расшифровывает password_enc из payload через Fernet.
  Каждый вызов обязательно записывается в audit_logs (user, ip, timestamp).
  Ответ содержит expires_in_seconds=30 — UI скрывает пароль через 30 секунд.
- `GET /audit-logs` — журнал всех расшифровок (только superuser).

**`core/app/api/v1/endpoints/api_keys.py`**
- `POST /auth/api-keys` — создать API-ключ для SIEM/SOAR интеграции.
  Raw key (формат: `easm_<urlsafe_token>`) возвращается ОДИН РАЗ, затем недоступен.
  В БД хранится только SHA-256 хеш. Только Enterprise-план или superuser.
- `GET /auth/api-keys` — список ключей (без raw key, только метаданные).
- `DELETE /auth/api-keys/{id}` — мягкий отзыв (is_active=False).

**`core/app/api/v1/endpoints/notifications.py`**
- `GET /notifications` — последние 50 уведомлений (непрочитанные первыми).
- `GET /notifications/count` — `{"unread": N}` для badge на колокольчике.
- `POST /notifications/{id}/read` — пометить прочитанным.
- `POST /notifications/read-all` — отметить все прочитанными.
- `GET /notifications/stream` — SSE-поток (EventSource): polling каждые 5 сек,
  heartbeat `: heartbeat\n\n`, graceful disconnect через request.is_disconnected().

**`core/app/api/v1/endpoints/graph.py`**
Neo4j Attack Path Engine:
- `GET /graph/{domain}/attack-paths` — список путей атаки для домена из Neo4j.
  IDOR-защита: домен должен принадлежать организации пользователя.
- `GET /graph/{domain}/visualization` — данные для Vis.js графа:
  nodes (assets, events, IPs, services) + edges (relationships).

**`core/app/api/v1/endpoints/mssp.py`**
MSSP Multi-Tenancy — управление клиентами агентства:
- `POST /mssp/clients` — создать клиентскую организацию (дочернюю).
- `GET /mssp/clients` — список клиентов MSSP (только mssp_parent_id = текущая org).
- `GET /mssp/clients/{id}/risk-score` — агрегированный Risk Score клиента.
- `GET /mssp/dashboard` — обзорный дашборд по всем клиентам с мини-gauge.

**`core/app/api/v1/endpoints/billing.py`**
- `GET /billing/plan` — информация о текущем тарифном плане:
  название, лимит доменов, количество использованных, остаток.
- `POST /billing/upgrade` — запрос на смену плана.

**`core/app/api/v1/endpoints/scheduled_scan.py`**
- `POST /schedule/` — создать расписание автоматического сканирования домена.
- `GET /schedule/` — список активных расписаний организации.
- `DELETE /schedule/{id}` — деактивировать расписание.
- `POST /schedule/trigger/{id}` — запустить сканирование немедленно вне расписания.
- `GET /schedule/beat-schedules` — список всех 6 Celery Beat задач с описанием расписания.

---

### Сервисы

**`core/app/services/webhook.py`**
Отправка webhook-уведомлений для critical-событий на webhook_url организации.
SSRF-защита через `_is_safe_webhook_url()`: блокирует RFC-1918 (192.168.x.x, 10.x.x.x,
172.16-31.x.x), loopback (127.x.x.x), link-local (169.254.x.x), metadata-адреса.
DNS-резолюция для проверки реального IP (обход через DNS rebinding).

**`core/app/services/opensearch_client.py`**
Async-клиент к OpenSearch с connection pool и retry (3 попытки, exponential backoff).
Два индекса:
- `easm-events` — все события, обычный маппинг.
- `easm-leaked-credentials` — credential-утечки, оптимизированный маппинг,
  ILM-политика: hot (7 дней) → warm (30 дней) → cold (90 дней) → delete.
Graceful degradation: если OpenSearch недоступен — логирует warning, не падает.

**`core/app/services/graph_client.py`**
Neo4j async-клиент (neo4j Python driver). Функции:
- `ensure_constraints()` — создаёт UNIQUE constraints при старте.
- `upsert_event_to_graph(event_data)` — добавляет событие в граф:
  узлы Domain, IP, Service, Vulnerability + рёбра HAS_IP, RUNS, HAS_VULN.
- `get_attack_paths(domain)` — Cypher-запрос: поиск путей от внешней точки к критическим активам.
Graceful degradation: если Neo4j недоступен — логирует, не падает.

**`core/app/services/report_generator.py`**
Генерация PDF-отчётов через ReportLab.
- `generate_technical_report(asset, events, risk_score)` — технический отчёт:
  все события с деталями, Risk Score, breakdown по severity, таблица рекомендаций.
- `generate_executive_report(asset, risk_score)` — executive summary:
  1 страница, Risk Score gauge, ТОП-3 угрозы, краткие выводы для руководства.

**`core/app/scanner.py`**
Легаси-модуль: прямой запуск subfinder/nmap/nuclei через subprocess (shell=False).
Используется scheduled_scan для ручного запуска сканирований.

---

## WORKERS — Celery задачи

### Инфраструктура воркеров

**`workers/celery_app.py`**
Celery-приложение: брокер Redis, backend Redis, JSON-сериализация.
Очереди: default, discovery, scanning, osint, parsing.
Настройки надёжности: task_acks_late=True, prefetch_multiplier=1.
Таймауты: soft 600с, hard 660с. Retry: 3 попытки, 60с между ними.
Beat-расписание (6 задач):
- subfinder all_active — ежедневно 02:00 UTC
- nuclei all_active — ежедневно 03:00 UTC
- port_scanner all_assets — ежедневно 04:00 UTC
- tech_profiler all_assets — ежедневно 05:00 UTC
- darknet ransomware — каждый час (minute=0)
- telegram monitor — каждые 15 минут

**`workers/config.py`**
WorkerSettings: REDIS_URL, CORE_API_URL, INTERNAL_API_SECRET, пути к бинарникам
(SUBFINDER_BIN, NUCLEI_BIN, GITLEAKS_BIN).

**`workers/crypto.py`**
Зеркало `core/app/core/crypto.py`: те же функции encrypt_password/decrypt_password.
Нужен воркерам чтобы шифровать пароли перед отправкой в core — raw пароли
никогда не покидают воркер в открытом виде.

**`workers/tasks/base.py`**
Базовый Celery Task класс с retry-логикой и structured logging.

**`workers/tasks/bulk_ingest.py`**
Хелпер `bulk_ingest(events: list[dict], core_api_url, secret)`:
отправляет батч событий в `POST /api/v1/internal/ingest/bulk`.
Используется всеми воркерами для отправки результатов в core.

---

### Сканирование инфраструктуры

**`workers/tasks/subfinder.py`**
Запуск subfinder (Go-binary) для нахождения поддоменов.
Парсит stdout, для каждого поддомена создаёт событие `subdomain_found`.
Функция `scan_domain_all_active()` — beat-задача: берёт все активные активы
через Core API и запускает subfinder для каждого.

**`workers/tasks/nuclei.py`**
Запуск Nuclei (Go-binary) — сканер уязвимостей по шаблонам.
Шаблоны: CVE, misconfiguration, exposed-panels, default-credentials.
Каждая найденная уязвимость → событие с severity из Nuclei CVSS.

**`workers/tasks/port_scanner.py`**
Сканирование открытых портов (nmap или masscan).
Top-1000 портов, детектирование сервисов (-sV).
Открытые нестандартные порты → события `exposed_service`.
`run_port_scan_all_assets()` — beat-задача для всех активов.

**`workers/tasks/domain_hardening.py`**
Проверка security headers: Content-Security-Policy, HSTS, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
Отсутствие критичных заголовков → события `hardening_issue`.

**`workers/tasks/takeover_detector.py`**
Subdomain takeover: резолюция CNAME для каждого поддомена.
Если CNAME указывает на отсутствующий сервис (GitHub Pages без репо, удалённый Heroku app,
S3 bucket не существует) → событие `subdomain_takeover` (high/critical).
База fingerprints: 50+ сервисов с сигнатурами ответов.

**`workers/tasks/tls_fingerprinter.py`**
TLS-анализ: срок истечения сертификата (за 30/14/7 дней → разные severity),
JA4-fingerprint (идентификация TLS-клиентских библиотек),
проверка цепочки доверия, слабые cipher suites (RC4, 3DES, NULL).

**`workers/tasks/s3_scanner.py`**
Перебор S3-бакетов по паттернам (company-name, company-backup, company-data и др.).
Проверка публичного доступа через HEAD-запрос.
Публичный бакет → событие `open_s3_bucket` (high).

**`workers/tasks/shodan_enricher.py`**
Обогащение данных активов через Shodan API.
Исторические данные о портах, баннеры сервисов, технологии, уязвимости CVE,
геолокация, ASN, организация-владелец IP.
Бесплатный план: 1 запрос/секунда. Без ключа — silent skip.

**`workers/tasks/tech_profiler.py`**
Wappalyzer-like детектирование технологий. Алгоритм:
1. HTTP GET домена (httpx, HTTPS→HTTP fallback, verify=False)
2. Сравнение заголовков/кук/тела с 35 сигнатурами
3. Извлечение версии regex-группами из Server/X-Powered-By
4. Проверка версии по EOL-базе (PHP, Nginx, Apache, IIS)
5. Severity: medium если EOL обнаружен, иначе info
Функция `run_tech_profiler_all_assets()` — beat-задача.

---

### OSINT и Threat Intelligence

**`workers/tasks/github_search.py`**
GitHub Code Search API: поиск по domain, email-паттернам, API-ключам.
Запросы: `"@company.com" AND (password OR secret OR key)`,
`site:domain.com password`, специфичные паттерны по названию компании.
Найденные секреты → события `github_secret_leak`.

**`workers/tasks/gitleaks.py`**
Запуск gitleaks (Go-binary) на конкретных GitHub-репозиториях.
Детектирует: AWS keys, private keys, JWT secrets, Telegram tokens и 150+ других паттернов.
Более глубокий анализ чем github_search — на уровне git diff.

**`workers/tasks/paste_monitor.py`**
Мониторинг paste-сервисов (Pastebin, dpaste, hastebin, GitHub Gist).
Поиск упоминаний домена, email-паттернов, IP-адресов.
Новое упоминание → событие `paste_mention`.

**`workers/tasks/phishing_detector.py`**
Генерация и проверка потенциальных фишинговых доменов:
- Typosquatting: transpositions, deletions, substitutions
- Homoglyph: замена букв похожими символами (0→o, rn→m и др.)
- Bitsquatting: однобитовые ошибки в ASCII
- Проверка регистрации через DNS-резолюцию
Зарегистрированные подозрительные домены → событие `phishing_domain`.

**`workers/tasks/human_osint.py`**
OSINT по сотрудникам компании:
- GitHub API: поиск по `@company.com` в профилях
- LinkedIn: DDG Lite search (`site:linkedin.com/in "company"`)
- Email-паттерны: firstname.lastname@, f.lastname@, flastname@
- VIP-детектирование: CEO, CTO, CISO, security-роли
- Данные: имя, должность, GitHub/LinkedIn ссылки, публичные email
Результат → события `employee_profile` с is_vip флагом.

**`workers/tasks/breach_checker.py`**
Проверка email-адресов по HaveIBeenPwned API v3.
k-anonymity модель: отправляет только первые 5 символов SHA-1 хеша email.
Найденные breaches → событие `breach_found` с деталями (breach_name, date, exposed_data).

**`workers/tasks/intelx_api.py`**
Intelligence X API — поисковик по даркнету, утечкам, I2P, Freenet, Tor.
Поиск по домену, email, IP. Возвращает ссылки на найденные записи с датами и bucket-типами.
Требует API-ключ IntelX.

**`workers/tasks/darknet_monitor.py`**
Оркестратор darknet-мониторинга: запускает IntelX API + ransomware_sites + paste_monitor.
Агрегирует результаты, дедуплицирует по деталям события.

**`workers/tasks/ransomware_sites.py`**
Мониторинг leak-сайтов ransomware-группировок через Tor.
Список отслеживаемых сайтов: LockBit, ALPHV/BlackCat, Cl0p, RansomHub, Play и др.
Ротация Tor-цепей через stem (NEWNYM) каждые N сайтов.
User-Agent ротация через fake_useragent.
Упоминание домена/компании → событие `darknet_mention` (high/critical).
`run_darknet_monitor_all_assets()` — beat-задача (каждый час).

**`workers/tasks/tor_client.py`**
HTTP-клиент поверх Tor через SOCKS5-прокси (127.0.0.1:9050).
Retry с повторным NEWNYM при ошибках соединения. Таймаут 30с.

---

### Стилер-логи

**`workers/tasks/stealer_parser.py`**
Парсинг ZIP-архивов стилер-логов. Форматы: Redline, Vidar, Raccoon, META.
Извлекает: логины, URL, пароли (шифрует через workers/crypto.py перед отправкой),
куки браузеров, данные кредитных карт (маскируются).
Дедупликация по sha256(login+url). Результат → bulk_ingest.

**`workers/tasks/stealer_tg_channels.py`**
Мониторинг Telegram-каналов стилеров через t.me/s/{channel} (публичные каналы).
Список известных каналов. Скачивает свежие посты, ищет ZIP-вложения с логами.
Тихое скачивание → передача в stealer_parser.

**`workers/tasks/stealer_sources.py`**
Оркестратор: запускает stealer_tg_channels + другие настроенные источники.

**`workers/tasks/cookie_validator.py`**
Проверка живых сессий украденных кук из стилер-архива.
Метод: HEAD-запросы к сессионным endpoint'ам (не генерирует логов на WAF/EDR жертвы).
HTTP 200/302 → сессия жива → событие `active_session_leak` (critical).

---

### Уведомления

**`workers/tasks/telegram_alerts.py`**
Отправка Telegram-алертов при поступлении событий.
Функция `dispatch_alerts(event, core_api_url, secret, bot_token)`:
1. Получает активные alert-правила организации через `/internal/alert-rules`
2. Фильтрует по severity (>= min_severity) и event_type
3. Форматирует сообщение: emoji по severity, тип события, домен, детали payload
4. Отправляет через Telegram Bot API в каждый подходящий chat_id
Вызывается из ingest.py в ThreadPoolExecutor (не блокирует ответ API).

**`workers/tasks/telegram_monitor.py`**
Мониторинг Telegram-каналов (не стилеров, а общих threat intelligence каналов):
поиск упоминаний отслеживаемых доменов.
`run_telegram_monitor_all_assets()` — beat-задача (каждые 15 минут).

---

## Базы данных и внешние сервисы

| Сервис | Назначение | Обязателен |
|--------|-----------|-----------|
| PostgreSQL | Основное хранилище (assets, events, users, org, api_keys, notifications, audit_log) | Да (или SQLite для dev) |
| Redis | Rate limiting, Celery broker+backend | Нет (fallback MemoryStorage) |
| OpenSearch | Полнотекстовый поиск событий, credential-индекс с ILM | Нет (graceful skip) |
| Neo4j | Attack Path граф, Cypher-запросы | Нет (graceful skip) |
| Telegram Bot API | Алерты в Telegram-чаты | Нет (нет токена = тихий skip) |
| Shodan API | Обогащение данных о хостах | Нет (нет ключа = skip) |
| IntelX API | Darknet поиск | Нет (нет ключа = skip) |
| HaveIBeenPwned API | Проверка breach | Нет (нет ключа = skip) |
| GitHub API | Поиск утечек в репозиториях | Нет (без токена = лимит 60/ч) |
| Tor (SOCKS5 :9050) | Darknet мониторинг | Нет (без Tor = skip) |

---

## Статический веб-интерфейс

**`core/static/index.html`** + **`core/static/app.js`** + **`core/static/style.css`**

Single-page application (vanilla JS, без фреймворков). Вкладки:
- **Dashboard** — Risk Score gauge (SVG 270°, анимация 800ms), топ-угрозы, последние события
- **Assets** — CRUD активов, быстрые кнопки запуска сканов
- **Events** — таблица событий с фильтрами, кнопка CSV-экспорта, кнопка 🔓 для reveal паролей
- **Alerts** — управление правилами Telegram-алертов
- **Scan** — ручной запуск всех типов сканирований
- **Darknet** — результаты darknet-мониторинга
- **Graph** — интерактивный граф атак (Vis.js Network, forceAtlas2Based)
- **Employees** — Human OSINT результаты, список сотрудников с профилями
- **Technologies** — результаты tech profiling, badge ⚠️ EOL / ✓ OK
- **Map** — дерево инфраструктуры (домен → поддомены → IP → порты → технологии)
- **MSSP** — дашборд клиентов агентства (скрыта для обычных пользователей)
- **API Keys** — управление ключами SIEM/SOAR (только Enterprise)
- **Audit** — журнал расшифровок паролей (только superuser)

Header: колокольчик 🔔 с badge непрочитанных, dropdown-панель уведомлений, кнопка «Отметить все»,
индикатор тарифного плана и лимита доменов.

---

## Миграции Alembic

| Файл | Что добавляет |
|------|--------------|
| `20260524_add_org_plan` | Поле plan в organizations, enum starter/professional/enterprise |
| `20260524_add_mssp_fields` | Поля MSSP: parent_id, is_mssp_provider, mssp_contract_start/end |
| `20260525_add_event_condition` | Поля condition (TEXT) и resolved_at в events |
| `20260525_add_audit_log` | Таблица audit_logs |
| `20260525_add_api_keys` | Таблица api_keys |
| `20260525_add_notifications` | Таблица notifications + составной индекс (org_id, is_read, created_at) |
