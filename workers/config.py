from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Подключение к брокеру и Core API
    REDIS_URL: str = "redis://redis:6379/0"
    CORE_API_URL: str = "http://core:8000"
    INTERNAL_API_SECRET: str = "INTERNAL_CHANGE_ME"

    # GitHub токен для поиска утечек
    GITHUB_TOKEN: str = ""

    # Путь к бинарникам инструментов внутри контейнера
    SUBFINDER_BIN: str = "/usr/local/bin/subfinder"
    NUCLEI_BIN: str = "/usr/local/bin/nuclei"
    GITLEAKS_BIN: str = "/usr/local/bin/gitleaks"

    # Прокси для cookie_validator (comma-separated, опционально)
    # Формат: http://user:pass@host:port,http://user:pass@host2:port
    COOKIE_PROXY_LIST: str = ""

    # Browserless CDP-эндпоинт для Playwright (ws://browserless:3000?token=...)
    # Если задан — локальный Chromium не запускается, нет риска зомби-процессов
    BROWSERLESS_URL: str = ""


settings = WorkerSettings()
