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

Как использовать эту инструкцию:

1.  Инициализируйте пустой git-репозиторий в рабочей папке.
2.  Запустите вашего CLI-агента (например, aider или активируйте расширение Roo
    Code в VS Code).
3.  Передайте текст инструкции в контекст агента.
4.  Дайте первую команду: «Initialize Phase 1 of the roadmap as defined in the
    system instructions. Create the folder structure, docker-compose.yml, and
    the FastAPI base with the NormalizedEvent schema».

