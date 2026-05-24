"""
Tor HTTP-клиент для EASM darknet-мониторинга.

Предоставляет:
  - get_tor_client()    — httpx.Client через SOCKS5 прокси Tor
  - check_tor_available() — проверка доступности Tor-сети

Принципы:
  - shell=False везде, никаких subprocess
  - Таймаут 30 секунд на все Tor-запросы
  - Graceful degradation: недоступность Tor не ронит всё приложение
  - DNS резолвится на стороне Tor-узла (socks5h, а не socks5)
"""
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Адрес SOCKS5-прокси Tor — локальный Tor-демон слушает 9050
_TOR_PROXY_URL = "socks5h://127.0.0.1:9050"

# Таймаут для Tor-запросов: .onion-сайты медленные, 30с — разумный минимум
_TOR_TIMEOUT = 30.0

# URL для проверки доступности Tor (возвращает JSON с полем IsTor)
_TOR_CHECK_URL = "https://check.torproject.org/api/ip"

# User-Agent для Tor-запросов — не раскрывает природу сканера
_TOR_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"
)


def get_tor_client() -> Optional[httpx.Client]:
    """
    Создаёт и возвращает httpx.Client с SOCKS5-прокси Tor.

    Использует socks5h — DNS резолвится на стороне Tor-узла выхода,
    что критично для .onion-адресов (они вообще не резолвятся локально).

    Возвращает:
        httpx.Client — настроенный клиент с Tor-прокси
        None — если httpx не поддерживает SOCKS5 (не установлен httpx[socks])

    Примечание: клиент не проверяет доступность Tor при создании.
    Используйте check_tor_available() для предварительной проверки.

    Caller обязан закрыть клиент через client.close() или использовать
    его как context manager.
    """
    try:
        client = httpx.Client(
            proxy=_TOR_PROXY_URL,
            timeout=_TOR_TIMEOUT,
            headers={
                "User-Agent": _TOR_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
            follow_redirects=True,
            # Отключаем верификацию SSL для .onion — у них нет валидных cert
            verify=False,
        )
        return client
    except Exception as exc:
        # Вероятно, httpx[socks] не установлен
        logger.warning(
            "[tor_client] Не удалось создать Tor-клиент: %s. "
            "Убедитесь что установлен httpx[socks]",
            exc,
        )
        return None


def check_tor_available() -> bool:
    """
    Проверяет доступность Tor-сети через check.torproject.org.

    Отправляет запрос через Tor-прокси к публичному API Tor Project,
    который возвращает {"IsTor": true/false, "IP": "..."}.

    Возвращает:
        True  — если Tor работает и запрос подтверждён как Tor-трафик
        False — если Tor недоступен (демон не запущен, таймаут, ошибка сети)
    """
    client = get_tor_client()
    if client is None:
        logger.warning("[tor_client] Tor-клиент недоступен (SOCKS5 не поддерживается)")
        return False

    try:
        with client:
            response = client.get(_TOR_CHECK_URL, timeout=_TOR_TIMEOUT)
            if response.status_code != 200:
                logger.warning(
                    "[tor_client] check.torproject.org вернул HTTP %d",
                    response.status_code,
                )
                return False

            data = response.json()
            is_tor: bool = bool(data.get("IsTor", False))
            ip_addr: str = data.get("IP", "unknown")

            if is_tor:
                logger.info("[tor_client] Tor доступен, выходной IP: %s", ip_addr)
            else:
                logger.warning(
                    "[tor_client] Запрос прошёл через %s, но НЕ через Tor", ip_addr
                )

            return is_tor

    except httpx.ConnectError as exc:
        # Tor-демон не запущен или порт 9050 недоступен
        logger.warning("[tor_client] Tor недоступен (ConnectError): %s", exc)
        return False
    except httpx.TimeoutException as exc:
        logger.warning("[tor_client] Tor недоступен (таймаут): %s", exc)
        return False
    except Exception as exc:
        logger.warning("[tor_client] Неожиданная ошибка при проверке Tor: %s", exc)
        return False
