# EASM Platform — External Attack Surface Management

Модульная платформа для мониторинга внешней поверхности атаки и Threat Intelligence.

## Архитектура

```
┌──────────────────────────────────────────────────────┐
│  Control Plane (/core)                               │
│  FastAPI · PostgreSQL · OpenSearch · JWT Auth        │
│  /api/v1/internal/ingest  ← принимает события        │
└──────────────────────┬───────────────────────────────┘
                       │ HTTP POST (shared secret)
┌──────────────────────▼───────────────────────────────┐
│  Data Plane (/workers)                               │
│  Celery · Redis · subfinder · nuclei · gitleaks      │
└──────────────────────────────────────────────────────┘
```

## Быстрый старт

```bash
cp .env.example .env
# отредактируй .env

docker compose up --build
```

API документация: http://localhost:8000/docs  
Flower (мониторинг воркеров): http://localhost:5555

## Роадмап

| Фаза | Статус |
|------|--------|
| 1. Core API + БД + Auth | ✅ Готово |
| 2. Asset Discovery (subfinder + nuclei) | 🚧 В работе |
| 3. Secret Leaks (gitleaks + stealer logs) | ⏳ Запланировано |
| 4. Alerts + Dashboard (Next.js) | ⏳ Запланировано |

## Тесты

```bash
cd core
pip install -r requirements-dev.txt
pytest tests/ -v --cov=app --cov-report=term-missing
```

## Безопасность

- JWT для пользовательского API
- Shared secret (Bearer) для внутреннего `/ingest` воркеров  
- Секреты маскируются на стороне воркера до отправки в Core
- Параметризованные запросы, `shell=False` во всех `subprocess.run`
