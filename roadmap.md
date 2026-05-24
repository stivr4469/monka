Ниже представлен прагматичный поэтапный план разработки (роадмап) и системная
инструкция для AI CLI-агента (например, Claude CLI, Aider, Roo Code или
аналогичных), настроенная на генерацию модульного и безопасного кода.

Роадмап разработки платформы (MVP)

Данный план рассчитан на постепенное усложнение архитектуры, начиная от
стабильного ядра и заканчивая распределенными парсерами.

[ Неделя 1-2 ] ──► [ Неделя 3-4 ] ──► [ Неделя 5-6 ] ──► [ Неделя 7-8 ]
База и Core API     Asset Discovery    Secret & Stealer    Alerts & UI
(FastAPI, DB, OS)   (Subfinder, Nuclei)  (Gitleaks, Logs)   (Webhooks, Frontend)

Этап 1: Фундамент и Core API (Недели 1–2)

  - Результат: Рабочее ядро системы, способное принимать, валидировать и
    сохранять нормализованные события.
  - Задачи:
    1.  Инициализация проекта (монорепозиторий с разделением на /core и
        /workers).
    2.  Проектирование схемы БД PostgreSQL (таблицы пользователей, организаций,
        отслеживаемых доменов/активов).
    3.  Развертывание локального окружения в Docker Compose (PostgreSQL,
        OpenSearch, Redis).
    4.  Создание FastAPI-приложения: авторизация (JWT), управление тенантами и
        CRUD для мониторинга активов.
    5.  Реализация защищенного внутреннего API-эндпоинта /api/v1/internal/ingest
        для приема данных от воркеров.

Этап 2: Модуль инвентаризации активов (Asset Discovery) (Недели 3–4)

  - Результат: Автоматическое сканирование инфраструктуры клиента сразу после
    добавления домена.
  - Задачи:
    1.  Создание Celery-воркера для запуска внешних утилит.
    2.  Интеграция subfinder для поиска поддоменов.
    3.  Интеграция nuclei для сканирования обнаруженных поддоменов на открытые
        панели и уязвимости.
    4.  Реализация парсеров вывода этих утилит в нормализованный JSON-формат
        (согласно схеме NormalizedEvent).
    5.  Логика дедупликации в Core API (чтобы не создавать инцидент повторно при
        каждом сканировании).

Этап 3: Поиск утечек и секретов (Git Leaks & Stealer Logs) (Недели 5–6)

  - Результат: Мониторинг публичных репозиториев на утечки ключей и базовый
    парсинг логов стилеров.
  - Задачи:
    1.  Разработка воркера для регулярного поиска по GitHub API (поиск
        упоминаний доменов компании).
    2.  Запуск gitleaks внутри контейнера для анализа найденных репозиториев.
    3.  Реализация модуля парсинга архивов стилеров (извлечение данных из
        текстовых файлов Passwords.txt, маскирование паролей на стороне
        воркера).
    4.  Индексация нормализованных данных в OpenSearch.

Этап 4: Система уведомлений и Дашборд (Недели 7–8)

  - Результат: Интерфейс для пользователя с визуализацией рисков и отправкой
    алертов.
  - Задачи:
    1.  Написание сервиса алертинга (отправка уведомлений в Telegram/Slack/Email
        при обнаружении критических событий).
    2.  Разработка REST API для дашборда (фильтрация инцидентов по критичности,
        поиск по OpenSearch).
    3.  Создание простого интерфейса на Next.js / Tailwind CSS (отображение
        списка активов, текущего Risk Score и таблицы инцидентов).


## 3. Your Execution Strategy (Agent Instructions)
1.  **Incremental, Test-Driven Development:** Do not attempt to write the entire system in one massive generation. Create files sequentially. Always generate a test file alongside the implementation.
2.  **Strict Error Handling:** Security tasks can fail due to network timeouts, rate-limiting, or unexpected input formats. Every external CLI call (`subprocess.run`) or API request must be wrapped in try-except blocks with robust logging.
3.  **No Mocking of Core Logic:** Write real code. Do not use placeholder comments like `# TODO: implement this`. If a function is needed, implement its core logic immediately.
4.  **Security First:** Use parameterized queries, avoid shell=True in subprocess calls, validate all inputs using Pydantic, and implement secure token generation for API auth.

## 4. Immediate Next Steps (Your First Task)
1.  Create the project directory structure:
    ├── core/
    │   ├── app/
    │   │   ├── api/
    │   │   ├── core/ (config, security)
    │   │   ├── models/ (SQLAlchemy models)
    │   │   ├── schemas/ (Pydantic schemas)
    │   │   └── main.py
    │   ├── tests/
    │   └── Dockerfile
    ├── workers/
    │   ├── tasks/
    │   ├── celery_app.py
    │   ├── tests/
    │   └── Dockerfile
    ├── docker-compose.yml
    └── README.md
2.  Initialize the `/core` directory, define the `NormalizedEvent` Pydantic model (with fields: event_type, severity, source_type, source_name, target_domain, payload, detected_at), and create a basic FastAPI skeleton with an `/ingest` endpoint.
3.  Provide the `docker-compose.yml` defining PostgreSQL, Redis, and OpenSearch services.

Begin by setting up the project structure and writing the initial files for Step 1.

---

## Фаза 5: Продвинутый Darknet Intelligence (Недели 9–10)

**Цель:** Реальный доступ к .onion и форумным данным без костылей.

### 5.1 Tor-инфраструктура
- Tor SOCKS5 прокси (socks5h://127.0.0.1:9050) в отдельном сервисе
- httpx-клиент с ротацией цепочек (NEWNYM через управляющий порт 9051)
- Таймауты и retry-логика под специфику Tor-сети

### 5.2 Прямой парсинг Ransomware Leak Sites
- LockBit 3.0, ALPHV/BlackCat, Play, Clop, RansomHub — прямые onion-адреса
- BeautifulSoup + регулярный мониторинг новых жертв
- Автообновление onion-адресов через GitHub-агрегаторы ransomwatch
- Severity: critical для совпадений по домену клиента

### 5.3 IntelX.io API Integration
- `/phonebook/search` — поиск по доменам в утёкших базах форумов (XSS, Exploit, BreachForums)
- Бесплатный тир: 100 запросов/день — достаточно для MVP
- Нормализация в EventType: `forum_mention`, severity: `high`

### 5.4 Расширенный RansomWatch
- Парсинг полного JSON-фида всех 100+ групп вымогателей
- Инкрементальная обработка (только новые посты с timestamp > last_run)

---

## Фаза 6: Production Hardening & Senior Code Review (Недели 11–12)

**Цель:** Код уровня production, готовый к первым коммерческим клиентам.

### 6.1 Senior Code Review
- [ ] Run full senior code review.
- [ ] Refactor weak parts.
- [ ] Optimize architecture.
- [ ] Add missing production features.

### 6.2 Архитектурные улучшения
- Устранить дублирование `_executor` и `sys.path` в каждом эндпоинте → вынести в `workers/client.py`
- Исправить баг `port` (undefined variable) в `scheduled_scan.py`
- Единый `WorkerClient` с retry/timeout вместо прямых `httpx.post`

### 6.3 Production-фичи
- Rate limiting на все публичные эндпоинты (slowapi)
- CORS whitelist из конфига (не хардкод `localhost:3000`)
- Пагинация событий (cursor-based, не offset)
- Export событий в CSV/JSON
- Webhook-нотификации при новом critical-событии
- Полная валидация входных данных (Pydantic strict mode)
- 80%+ test coverage (pytest + httpx AsyncClient)

### 6.4 Frontend Production
- Тёмная тема с переключателем
- Real-time polling событий (SSE или WebSocket)
- Фильтрация таблицы событий по severity/type/domain
- Risk Score дашборд на главной странице
- Mobile-responsive вёрстка

---

---

## Фаза 7: Масштабируемость и Production-оптимизация (Аудит)

**Цель:** Устранить архитектурные ограничения при экстремальных нагрузках.
**Источник:** Технический аудит кодовой базы (май 2026).

---

### 7.A Стриминговый парсинг ZIP-архивов стилеров (OOM-fix)

**Проблема:** `parse_stealer_log(file_bytes: bytes)` загружает весь ZIP в RAM → OOM на файлах >1GB.

- [ ] **7.A.1** В эндпоинте загрузки стилера (`POST /api/v1/stealer/upload`) — сохранять файл на диск (`/tmp/stealer_<uuid>.zip`) вместо `await file.read()` в память
- [ ] **7.A.2** Переписать `workers/tasks/stealer_parser.py` — принимать `file_path: Path` вместо `file_bytes: bytes`, открывать `zipfile.ZipFile(file_path)` с диска
- [ ] **7.A.3** Построчная итерация файлов внутри ZIP через `io.TextIOWrapper(zf.open(member))` без буферизации в RAM
- [ ] **7.A.4** После обработки удалять временный файл с диска
- [ ] **7.A.5** Добавить тест: парсинг ZIP-файла 100MB без превышения 50MB RAM

### 7.B Bulk Ingest API (устранение N×HTTP бутылочного горлышка)

**Проблема:** Каждая запись → отдельный `httpx.post()` → 10,000 записей = 10,000 HTTP-запросов.

- [ ] **7.B.1** Добавить схему `BulkIngestRequest(events: list[NormalizedEvent], max_length=1000)` в `core/app/schemas/normalized_event.py`
- [ ] **7.B.2** Реализовать `POST /api/v1/internal/ingest/bulk` в `core/app/api/v1/endpoints/ingest.py` — один запрос к БД для проверки дублей (`dedup_hash IN (...)`), `db.add_all()` для вставки
- [ ] **7.B.3** Добавить `bulk_ingest()` helper в `workers/tasks/` — накапливает батч до 500 записей, отправляет одним POST
- [ ] **7.B.4** Переключить `darknet_monitor.py` на батчевую отправку вместо построчной
- [ ] **7.B.5** Переключить `stealer_parser.py` на батчевую отправку
- [ ] **7.B.6** Добавить тест: 1000 событий bulk insert быстрее 10 секунд

### 7.C OpenSearch как Data Lake для событий

**Проблема:** Все события хранятся в PostgreSQL → деградация при >10M записей, нет fuzzy-поиска.

- [ ] **7.C.1** В `core/app/api/v1/endpoints/ingest.py` — после записи в PostgreSQL дублировать событие в OpenSearch (`opensearch_client.index()`) асинхронно (не блокировать ответ)
- [ ] **7.C.2** Создать `core/app/services/opensearch_client.py` — обёртка над `opensearch-py` с connection pool и retry
- [ ] **7.C.3** Создать индекс `easm-events` с маппингом (`keyword` для `event_type`/`severity`, `text` для `payload`)
- [ ] **7.C.4** Добавить `GET /api/v1/events/search?q=<fulltext>` — поиск через OpenSearch с fallback на PostgreSQL если OS недоступен
- [ ] **7.C.5** Сохранить PostgreSQL как source of truth для метаданных; OS только для поиска

### 7.D Domain Hardening — EASM периметр-чек

**Проблема:** Платформа ищет утечки пассивно, но не проверяет активные дыры в периметре.

- [ ] **7.D.1** Установить `dnspython` в `workers/requirements.txt`
- [ ] **7.D.2** Создать `workers/tasks/domain_hardening.py` — проверки: SPF TXT-запись, DMARC на `_dmarc.<domain>`, DNS Zone Transfer (AXFR), просроченный SSL-сертификат
- [ ] **7.D.3** Каждая найденная проблема → `NormalizedEvent(event_type="vulnerability", severity=medium/high/critical, source_name="domain_hardening")`
- [ ] **7.D.4** Добавить `POST /api/v1/scan/hardening` эндпоинт в core (аналогично `/scan/darknet`)
- [ ] **7.D.5** Добавить кнопку «Проверить периметр» в UI на вкладке Scan
- [ ] **7.D.6** Добавить тест: SPF-отсутствие на домене без TXT → severity=medium событие

---

## Фаза 8: EASM + DRPS — Собственный Data Lake и Recon Pipeline (new_vision.md)

**Цель:** Убрать зависимость от платных API, накопить собственные данные, реализовать полноценный инфраструктурный конвейер разведки.
**Источник:** BRD документ new_vision.md (май 2026).

---

### 8.A Certificate Transparency — пассивный сбор поддоменов

**Проблема:** subfinder частично покрывает CT-логи, но нет прямого запроса к crt.sh по домену.

- [x] **8.A.1** Добавить функцию `fetch_crt_sh(domain)` в `workers/tasks/subfinder.py` — GET `https://crt.sh/?q=%.{domain}&output=json`, извлекать `name_value`, дедуплицировать
- [x] **8.A.2** Результаты crt.sh слать через `bulk_ingest()` как `event_type=subdomain, source_name=crt.sh`
- [ ] **8.A.3** Добавить ASN/IP resolution — для каждого поддомена резолвить IP через `socket.getaddrinfo`, сохранять в payload
- [ ] **8.A.4** Маркировать IP крупных облаков (AWS/GCP/Azure/Cloudflare) через ip-ranges JSON — флаг `cloud_provider` в payload

---

### 8.B Risk Score — улучшение формулы (Time Decay + Asset Importance)

**Проблема:** Текущий Risk Score — простая сумма весов без учёта давности события и важности актива.

- [x] **8.B.1** В `GET /api/v1/assets/{id}/risk-score` — заменить формулу: `S = max(0, 100 - Σ W(sev_i) × T(t_i) × A(importance_i))`
- [x] **8.B.2** Реализовать `T(t) = e^(-0.005 × Δt_days)` — события давностью 140 дней весят вдвое меньше
- [x] **8.B.3** Веса: `critical=25, high=10, medium=4, low=1, info=0` (было: 25/10/5/0)
- [x] **8.B.4** Добавить поле `asset_importance` (float, default=1.0) в модель Asset — основной домен = 1.5, поддомен = 0.7
- [ ] **8.B.5** Эндпоинт `PATCH /api/v1/assets/{id}` — принимать `importance` (0.1–2.0) для ручной настройки

---

### 8.C Phishing Domain Detection — тайпосквоттинг

**Проблема:** Конкуренты не предлагают обнаружение фишинговых доменов. Это наше конкурентное преимущество.

- [x] **8.C.1** Создать `workers/tasks/phishing_detector.py` — генерация тайпосквот-вариантов домена (замена букв, добавление дефиса, перестановки)
- [x] **8.C.2** Проверка регистрации через DNS резолв — если домен резолвится и похож на целевой — событие
- [x] **8.C.3** `NormalizedEvent(event_type="vulnerability", severity="high", source_name="phishing_detector", payload={"typosquat": "v1sa.com", "original": "visa.com", "technique": "vowel_swap"})`
- [x] **8.C.4** Добавить `POST /api/v1/scan/phishing` эндпоинт — запуск в фоне
- [x] **8.C.5** Добавить кнопку «Проверить фишинг» в UI на вкладке Darknet рядом с «Проверить периметр»

---

### 8.D Telegram — расширение до 25+ каналов

**Проблема:** Текущий список DEFAULT_LEAK_CHANNELS — только 6 каналов. В new_vision.md указано 50+.

- [x] **8.D.1** Расширить `DEFAULT_LEAK_CHANNELS` в `workers/tasks/telegram_monitor.py` до 25+ каналов: добавить LummaC2Logs, StealerLogs, logsmafia, leaks_logs, combolists, dumpz_to и другие публичные каналы утечек

---

### 8.E PDF-отчёт по безопасности

**Проблема:** Нет автоматической генерации отчёта для клиента / совета директоров.

- [ ] **8.E.1** Добавить `reportlab` или `weasyprint` в `core/requirements.txt`
- [ ] **8.E.2** Создать `core/app/services/report_generator.py` — шаблон отчёта: Risk Score, топ-10 событий, разбивка по категориям (Сеть/Почта/Утечки/Веб)
- [ ] **8.E.3** Добавить `GET /api/v1/assets/{id}/report.pdf` — генерация и отдача PDF
- [ ] **8.E.4** Кнопка «Скачать отчёт PDF» в UI на вкладке Assets

---

### 8.F Phishing + Asset Drift — оповещение об изменениях периметра

**Проблема:** Нет уведомления когда на периметре появился новый поддомен или порт.

- [ ] **8.F.1** В `workers/tasks/subfinder.py` — при обнаружении нового поддомена (не существовал в Assets) — severity=medium вместо info
- [ ] **8.F.2** Добавить поле `first_seen_at` в модель Event — для отображения когда впервые замечен актив
- [ ] **8.F.3** На дашборде — виджет «Новые активы за 24 часа»

---

### 8.G Masscan + Nmap интеграция (порты)

**Проблема:** Нет сканирования открытых портов — это core EASM-функция.

- [ ] **8.G.1** Создать `workers/tasks/port_scanner.py` — запуск `nmap -p top1000 --open -T4 {ip}` через subprocess (shell=False)
- [ ] **8.G.2** Парсить вывод nmap XML (`-oX -`) — извлекать port/state/service/version
- [ ] **8.G.3** `NormalizedEvent(event_type="exposed_service", severity=medium, source_name="nmap", payload={"port": 8080, "service": "http", "version": "Apache 2.4.41", "ip": "1.2.3.4"})`
- [ ] **8.G.4** Добавить `POST /api/v1/scan/ports` эндпоинт
- [ ] **8.G.5** Добавить чипсел «Ports» в модуль-выборе на вкладке Scan

---

### 8.H S3 Bucket Discovery

**Проблема:** Открытые S3-корзины с данными компании — частая и критичная уязвимость.

- [ ] **8.H.1** Создать `workers/tasks/s3_scanner.py` — генерация имён бакетов по шаблонам: `{company}-prod`, `{company}-backup`, `{company}-assets`, `{company}-logs` и т.д. (50+ шаблонов)
- [ ] **8.H.2** HEAD-запрос к `https://{bucket}.s3.amazonaws.com` — если 200/403 → бакет существует; если `x-amz-bucket-region` в хедерах — открыт
- [ ] **8.H.3** `NormalizedEvent(event_type="exposed_service", severity="critical", source_name="s3_scanner")`
- [ ] **8.H.4** Добавить `POST /api/v1/scan/s3` эндпоинт

---

### 8.I SaaS Тарифные планы (Billing)

**Проблема:** Нет ограничений по тарифу — все клиенты получают неограниченный доступ.

- [ ] **8.I.1** Добавить поле `plan` (enum: starter/professional/enterprise) в модель Organization
- [ ] **8.I.2** Лимиты: starter=3 домена, professional=10, enterprise=безлимит
- [ ] **8.I.3** В `POST /api/v1/assets/` — проверять лимит доменов по плану → 402 Payment Required если превышен
- [ ] **8.I.4** На дашборде — бейдж текущего плана и счётчик использованных доменов

---

### 8.J Senior Code Review (финальная проверка)

- [ ] Run full senior code review.
- [ ] Refactor weak parts.
- [ ] Optimize architecture.
- [ ] Add missing production features.

---

## Фаза 9: Глубокая разведка и Attack Path Engine (new_vision.md v2)

**Цель:** Реализовать уникальные конкурентные преимущества платформы — Neo4j граф
путей атак, Session Cookie Validation, JA4 fingerprinting, MSSP UI и Human OSINT.
**Источник:** BRD new_vision.md Разделы 2–7 (обновлён май 2026).

---

### 9.A JA4/TLS Fingerprinting — детекция WAF и теневой инфраструктуры

**Зачем:** Определить скрытые WAF, балансировщики, C2-панели по TLS-отпечатку.

- [ ] **9.A.1** Установить `ja4` / `tlsfinger` или использовать `pyopenssl` + ручной анализ хендшейка
- [ ] **9.A.2** Создать `workers/tasks/tls_fingerprinter.py` — подключение через `ssl.SSLContext`, извлечение cipher suites, extensions, TLS version → JA4 hash
- [ ] **9.A.3** Сравнивать JA4-хеш с базой WAF-сигнатур (Cloudflare=X, AWS WAF=Y, Akamai=Z)
- [ ] **9.A.4** `NormalizedEvent(event_type="tls_fingerprint", severity="info/medium", payload={"ja4": "...", "waf_detected": "Cloudflare"})`
- [ ] **9.A.5** Добавить `POST /api/v1/scan/tls` эндпоинт
- [ ] **9.A.6** Добавить кнопку «TLS/JA4 Scan» в UI на вкладке Scan

---

### 9.B Subdomain Takeover Detection

**Зачем:** CNAME на удалённый удалённый сервис = возможность захвата поддомена.

- [ ] **9.B.1** В `workers/tasks/subfinder.py` — для каждого поддомена с CNAME-записью проверять статус внешнего ресурса
- [ ] **9.B.2** Список уязвимых fingerprints: GitHub Pages (404 + "There isn't a GitHub Pages site here"), S3 (NoSuchBucket), Heroku (No such app), Shopify, Fastly
- [ ] **9.B.3** При совпадении fingerprint → `NormalizedEvent(event_type="vulnerability", severity="critical", source_name="takeover_detector")`
- [ ] **9.B.4** Добавить тест: мок CNAME + 404 с GitHub fingerprint → critical событие

---

### 9.C Session Cookie Validation — УНИКАЛЬНАЯ ФИЧА

**Зачем:** Живые session cookies из стилер-логов = прямой доступ к системам без пароля.
Нет у конкурентов. Максимальный risk score при обнаружении.

- [ ] **9.C.1** В `workers/tasks/stealer_parser.py` — парсить секцию Cookies (Netscape/JSON формат) из ZIP-архивов стилеров
- [ ] **9.C.2** Создать `workers/tasks/cookie_validator.py` — для каждого найденного session cookie
- [ ] **9.C.3** Отправлять пассивный `HEAD` запрос к оригинальному хосту (из поля `host` куки) с заголовком `Cookie: <leaked_cookie_value>`
- [ ] **9.C.4** Анализировать ответ: HTTP 200/302 без redirect на login = **ЖИВАЯ СЕССИЯ**; 401/403/redirect → expired
- [ ] **9.C.5** Живая сессия → `NormalizedEvent(event_type="active_session_leak", severity="critical", payload={"host": "...", "user": "...", "cookie_name": "...", "session_alive": true})`
- [ ] **9.C.6** Мёртвая сессия → `NormalizedEvent(severity="medium", payload={"session_alive": false})`
- [ ] **9.C.7** Добавить `POST /api/v1/scan/cookies` эндпоинт — запуск валидации для конкретного stealer_log_id
- [ ] **9.C.8** В UI — иконка "🔴 LIVE SESSION" рядом с соответствующей записью в стилер-логах

---

### 9.D Human OSINT — профилирование сотрудников

**Зачем:** Определить VIP-цели для фишинга и вектор компрометации через сотрудников.

- [ ] **9.D.1** Создать `workers/tasks/human_osint.py` — поиск профилей по паттерну `site:linkedin.com "<domain>"` через DuckDuckGo/SerpAPI
- [ ] **9.D.2** Извлекать имена → генерировать паттерны корпоративной почты: `{f}.{last}@domain.com`, `{first}@domain.com`, `{first}{last}@domain.com`
- [ ] **9.D.3** Поиск GitHub аккаунтов разработчиков компании через GitHub API `GET /search/users?q={domain}+in:email`
- [ ] **9.D.4** `NormalizedEvent(event_type="human_intel", severity="low", payload={"name": "John Doe", "title": "DevOps Engineer", "email_pattern": "j.doe@target.com", "linkedin_url": "..."})`
- [ ] **9.D.5** Добавить `POST /api/v1/scan/human-osint` эндпоинт
- [ ] **9.D.6** Добавить вкладку «Сотрудники» в UI с таблицей найденных профилей

---

### 9.E Neo4j Attack Path Engine — граф путей атаки

**Зачем:** Связать все находки в единую модель и математически доказать возможность атаки.

- [ ] **9.E.1** Добавить `neo4j` в `docker-compose.yml` (neo4j:5, bolt port 7687)
- [ ] **9.E.2** Добавить `neo4j` Python driver в `core/requirements.txt`
- [ ] **9.E.3** Создать `core/app/services/graph_client.py` — асинхронный Neo4j клиент с retry
- [ ] **9.E.4** Схема нод: `Domain`, `Asset` (subdomain), `IPAddress`, `Port`, `Vulnerability`, `CredentialLeak`, `StealerLog`
- [ ] **9.E.5** Схема рёбер: `has_subdomain`, `has_ip`, `has_port`, `has_vuln`, `member_of_asn`, `associated_with`, `leaked_in`
- [ ] **9.E.6** В `ingest.py` — после записи события в PostgreSQL создавать/обновлять нод в Neo4j
- [ ] **9.E.7** При `severity=critical` события — запускать Cypher `MATCH p=shortestPath((a:External)-[*]→(c:CrownJewel))` для поиска пути атаки
- [ ] **9.E.8** Если путь найден — генерировать системный алерт `attack_path_found` с Risk Score=100
- [ ] **9.E.9** Добавить `GET /api/v1/assets/{domain}/attack-graph` — возвращает JSON графа для визуализации
- [ ] **9.E.10** Визуализировать граф в UI через D3.js или Vis.js

---

### 9.F MSSP Multi-Tenancy UI — панель партнёра

**Зачем:** MSSP-провайдеры управляют безопасностью сотен клиентов — нужна общая панель.

- [ ] **9.F.1** Добавить роль `mssp_operator` в модель User — может видеть все организации своего MSSP-аккаунта
- [ ] **9.F.2** Создать `GET /api/v1/mssp/clients` — список всех клиентов с текущим Risk Score и тенденцией (дельта за 24ч)
- [ ] **9.F.3** Добавить вкладку «Клиенты» в UI (только для роли mssp_operator)
- [ ] **9.F.4** Таблица клиентов: название, домен, Risk Score, delta(24h), количество критических событий
- [ ] **9.F.5** Сортировка по деградации рейтинга по умолчанию (самые опасные ситуации наверху)
- [ ] **9.F.6** Цветовая индикация: 80–100=зелёный, 60–79=жёлтый, 40–59=оранжевый, 0–39=красный

---

### 9.G Executive PDF Report — отчёт для руководства

**Зачем:** Технический PDF для инженеров (8.E) + Executive Report для CEO/CFO/страховщиков.

- [ ] **9.G.1** Создать второй шаблон в `core/app/services/report_generator.py` — Executive Report
- [ ] **9.G.2** Содержимое: Risk Score в сравнении с индустрией (gauge chart), топ-3 критических риска простым языком, тренд за 30 дней, финансовая оценка рисков (ориентировочный ущерб)
- [ ] **9.G.3** Добавить `GET /api/v1/assets/{id}/executive-report.pdf` эндпоинт
- [ ] **9.G.4** Кнопка «Executive Report» в UI рядом с технической кнопкой «Скачать PDF»

---

### 9.H Обновление Risk Score Engine (λ=0.003, обновлённые веса)

**Зачем:** new_vision.md v2 уточнил параметры: λ=0.003 (не 0.005), новые веса штрафов.

- [ ] **9.H.1** Обновить `T(t) = e^(-0.003 × t)` — снижение на 50% за 231 день (6 месяцев), было 140 дней
- [ ] **9.H.2** Обновить матрицу весов по таблице из BRD:
    - critical=25 (RCE, SQLi, живой session cookie)
    - high=15 (утекший пароль от внутренней системы)
    - high=12 (открытый порт БД / панель администрирования)
    - medium=8 (отсутствие SPF/DMARC)
    - low=3 (устаревшее ПО End-of-Life)
- [ ] **9.H.3** Добавить `condition` к каждому событию — условие когда штраф снимается (пароль сменён, порт закрыт)
- [ ] **9.H.4** Показывать в UI «До устранения» рядом с каждым штрафом

---

### 9.I OpenSearch Mapping — оптимизированный индекс для утечек

**Зачем:** Текущий easm-events индекс не оптимизирован для 50k записей/сек и 5B записей.

- [ ] **9.I.1** Создать отдельный индекс `easm-leaked-credentials` с настройками из BRD:
    - `number_of_shards: 5`, `number_of_replicas: 1`
    - `refresh_interval: "10s"` (вместо 1s по умолчанию)
    - `codec: "best_compression"`
- [ ] **9.I.2** Применить mapping: `login` как text+keyword, `password_enc` с `index: false`
- [ ] **9.I.3** Переключить `stealer_parser.py` на запись в `easm-leaked-credentials` вместо `easm-events`
- [ ] **9.I.4** ILM policy: горячая фаза 30 дней → тёплая (merge segments) → холодная (readonly) после 90 дней

---

### 9.J Shodan / Censys API — обогащение данных историческими сканами

**Зачем:** Выявить хосты, временно закрытые файрволом во время скана, но открытые вчера.

- [ ] **9.J.1** Добавить `SHODAN_API_KEY` и `CENSYS_API_ID`/`CENSYS_API_SECRET` в `.env`
- [ ] **9.J.2** Создать `workers/tasks/shodan_enricher.py` — `GET api.shodan.io/shodan/host/{ip}` для каждого IP из Asset
- [ ] **9.J.3** Сравнивать исторические порты Shodan с текущими нашими — расхождение → событие `asset_drift`
- [ ] **9.J.4** Добавить `POST /api/v1/scan/enrich` эндпоинт
- [ ] **9.J.5** Fallback: если нет API-ключей — пропускать этап без ошибки

---

### 9.K Senior Code Review v2 (после Фазы 9)

- [ ] Run full senior code review.
- [ ] Refactor weak parts.
- [ ] Optimize architecture.
- [ ] Add missing production features.

---

## Как использовать эту инструкцию:

1.  Инициализируйте пустой git-репозиторий в рабочей папке.
2.  Запустите вашего CLI-агента (например, aider или активируйте расширение Roo
    Code в VS Code).
3.  Передайте текст инструкции в контекст агента.
4.  Дайте первую команду: «Initialize Phase 1 of the roadmap as defined in the
    system instructions. Create the folder structure, docker-compose.yml, and
    the FastAPI base with the NormalizedEvent schema».


---

## Фаза 10: Production UX, Enterprise Features & Full Automation

**Цель:** Закрыть оставшиеся пункты BRD new_vision.md — Technology Profiling,
Audit Log, анимированный Risk Score, Asset Map, CSV-экспорт, API-ключи,
Stripe-биллинг и Celery Beat автоматизация полного скана.
**Источник:** BRD new_vision.md Разделы 2,7,8 (Фаза 5 Milestones).

---

### 10.A Technology Profiling — Wappalyzer-like детекция технологий (Этап 6 конвейера)

**Зачем:** Определить CMS, фреймворки, версии ПО. End-of-Life tracking — устаревшее ПО = уязвимость.

- [ ] **10.A.1** Создать `workers/tasks/tech_profiler.py` — HTTP GET к домену, анализ заголовков (Server, X-Powered-By, Via), кук (PHPSESSID, laravel_session, wp-settings), мета-тегов (generator), JavaScript переменных
- [ ] **10.A.2** Сигнатурная база: 30+ технологий (WordPress, Drupal, Joomla, Laravel, Django, Rails, React, Vue, Next.js, Nginx, Apache, IIS, Cloudflare, AWS)
- [ ] **10.A.3** End-of-Life mapping: dict `{"nginx": {"1.18": "2020-04-21", ...}}` — если версия EOL → `severity="medium"`, event_type="tech_eol"
- [ ] **10.A.4** `NormalizedEvent(event_type="tech_profile", severity="info/medium", payload={"technologies": [...], "eol_detected": [...]})`
- [ ] **10.A.5** Добавить `POST /api/v1/scan/tech-profile` эндпоинт с rate limit 5/min
- [ ] **10.A.6** Вкладка «Технологии» в UI — таблица технологий с badge EOL

---

### 10.B Password Decrypt + Audit Log

**Зачем:** BRD явно требует кнопку «Расшифровать пароль» с audit-log (кто, когда, с какого IP).

- [ ] **10.B.1** Создать модель `AuditLog` (таблица audit_logs): user_id, action, target_id, ip_address, user_agent, created_at
- [ ] **10.B.2** Миграция Alembic для audit_logs
- [ ] **10.B.3** Создать эндпоинт `GET /api/v1/events/{event_id}/reveal` — расшифровывает password_enc для событий с stealer/breach source_type, пишет в audit_log. Rate limit 10/hour per user.
- [ ] **10.B.4** `GET /api/v1/audit-logs` (только superuser) — список последних 500 обращений к reveal
- [ ] **10.B.5** В UI — кнопка «🔓 Расшифровать» в списке событий утечек (только для plan=professional/enterprise). Показывает пароль в модальном окне на 30 секунд, затем скрывает.
- [ ] **10.B.6** Вкладка «Аудит» (только superuser) — таблица audit_logs

---

### 10.C Risk Score Animated SVG Gauge

**Зачем:** BRD явно описывает "Risk Score Dial: круговой анимированный рейтинг (зелёный → красный)".

- [ ] **10.C.1** Заменить текстовый score на SVG-gauge: дуга 270° с анимацией CSS transition
- [ ] **10.C.2** Цвет по score: 75–100 = зелёный (#10b981), 40–74 = оранжевый (#f59e0b), 0–39 = красный (#ef4444)
- [ ] **10.C.3** Число score внутри дуги, уровень (low/medium/high/critical) под числом
- [ ] **10.C.4** Анимация появления: дуга рисуется от 0 до score за 800ms при загрузке
- [ ] **10.C.5** Также добавить мини-gauge в карточки MSSP-клиентов

---

### 10.D CSV Export событий

**Зачем:** BRD: "Технический PDF/CSV для инженеров". Текущий код PDF есть, CSV — нет.

- [ ] **10.D.1** `GET /api/v1/events/export?format=csv&asset_id=X&severity=critical` — StreamingResponse с CSV
- [ ] **10.D.2** Поля: id, event_type, severity, source_type, source_name, target_domain, detected_at, condition
- [ ] **10.D.3** Защита: только события своей организации (через asset_id ownership check)
- [ ] **10.D.4** Кнопка «⬇ CSV» в UI рядом с таблицей событий (скачивает текущий фильтр)

---

### 10.E Asset Map — Интерактивное дерево поддоменов

**Зачем:** BRD: "Asset Map: интерактивное дерево поддоменов и IP".

- [ ] **10.E.1** `GET /api/v1/assets/{asset_id}/map` — JSON дерево: домен → поддомены → IP → порты → технологии
- [ ] **10.E.2** Данные строятся из Event.payload (события port_scan, tls_fingerprint, tech_profile, subdomain_found)
- [ ] **10.E.3** Collapsible дерево в UI через vanilla JS — узлы раскрываются кликом
- [ ] **10.E.4** Иконки по типу узла: 🌐 домен, 📡 поддомен, 🔌 IP, 🚪 порт, ⚙️ технология

---

### 10.F API Keys для SIEM/SOAR интеграции (Enterprise)

**Зачем:** BRD: "SIEM/SOAR API — выгрузка для аудита" (Enterprise plan).

- [ ] **10.F.1** Модель `ApiKey`: id, user_id, name, key_hash (SHA-256), permissions (JSON), created_at, last_used_at, expires_at
- [ ] **10.F.2** Миграция Alembic
- [ ] **10.F.3** `POST /api/v1/auth/api-keys` — создать ключ (возвращает raw key только один раз)
- [ ] **10.F.4** `GET /api/v1/auth/api-keys` — список ключей (без raw значений)
- [ ] **10.F.5** `DELETE /api/v1/auth/api-keys/{key_id}` — отозвать ключ
- [ ] **10.F.6** Middleware/dependency `verify_api_key` — Bearer authentication альтернатива JWT для read-only endpoints
- [ ] **10.F.7** UI: секция «API Keys» в настройках (только план enterprise)

---

### 10.G Stripe Billing — Upgrades

**Зачем:** BRD явно описывает SaaS монетизацию. Текущий billing API без реального Stripe.

- [ ] **10.G.1** Добавить `STRIPE_SECRET_KEY` и `STRIPE_WEBHOOK_SECRET` в .env
- [ ] **10.G.2** `POST /api/v1/billing/checkout` — создать Stripe Checkout Session для upgrade плана
- [ ] **10.G.3** `POST /api/v1/billing/webhook` — обработчик Stripe событий (checkout.session.completed, customer.subscription.updated/deleted)
- [ ] **10.G.4** При успешной оплате — обновить org.plan в БД
- [ ] **10.G.5** UI: кнопка «Улучшить план» → редирект на Stripe Checkout

---

### 10.H Celery Beat — Полная автоматизация скана

**Зачем:** Сканирование должно работать без ручного запуска — автоматически каждые N часов.

- [ ] **10.H.1** Создать `workers/celery_config.py` с `beat_schedule`: subdomain каждые 24ч, port scan каждые 24ч, tech_profile каждые 24ч, darknet каждые 1ч, telegram каждые 15мин
- [ ] **10.H.2** `GET /api/v1/scheduled-scans` — текущее расписание и last_run для каждого модуля
- [ ] **10.H.3** `POST /api/v1/scheduled-scans/{scan_type}/trigger` — немедленный запуск (для superuser)
- [ ] **10.H.4** `PATCH /api/v1/scheduled-scans/{scan_type}` — изменить интервал (Enterprise)
- [ ] **10.H.5** Хранить last_run, next_run, status (running/idle/error) в Redis (key: scan_status:{org_id}:{scan_type})
- [ ] **10.H.6** UI: вкладка «Расписание» — таблица сканов с last_run и кнопкой «Запустить сейчас»

---

### 10.I Notifications Hub — Центр уведомлений

**Зачем:** Реальное время важнее email. Пуш-уведомления в UI при появлении critical событий.

- [ ] **10.I.1** SSE-эндпоинт `GET /api/v1/notifications/stream` — Server-Sent Events поток новых событий
- [ ] **10.I.2** При ingest critical события → публикация в Redis Pub/Sub channel `notifications:{org_id}`
- [ ] **10.I.3** SSE-хендлер подписывается на Redis Pub/Sub и пушит в EventSource клиента
- [ ] **10.I.4** UI: notification bell icon в шапке, badge с числом непрочитанных, dropdown список
- [ ] **10.I.5** `POST /api/v1/notifications/{id}/read` — пометить прочитанным
- [ ] **10.I.6** Модель Notification: id, org_id, event_id, message, is_read, created_at + миграция

---

### 10.J Senior Code Review Phase 10

- [ ] Полный security review фазы 10
- [ ] Рефакторинг слабых мест
- [ ] Финальная проверка production-readiness

