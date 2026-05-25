"""
Neo4j граф-клиент — Attack Path Engine (задача 9.E).

Graceful degradation: если NEO4J_URI не задан или сервер недоступен,
все публичные функции возвращают пустой результат без исключений.

Схема нод:
    (Domain  {name})                   — корневой домен
    (Asset   {fqdn, ip})               — поддомен / IP
    (Port    {number, ip, service})    — открытый порт
    (Vulnerability {name, severity})   — уязвимость (nuclei template_id)
    (CredentialLeak {email})           — утечка учётных данных
    (StealerLog {filename})            — источник утечки

Рёбра:
    (Domain)-[:HAS_SUBDOMAIN]  ->(Asset)
    (Asset) -[:HAS_PORT]       ->(Port)
    (Port)  -[:HAS_VULN]       ->(Vulnerability)
    (Domain)-[:ASSOCIATED_WITH]->(CredentialLeak)
    (CredentialLeak)-[:LEAKED_IN]->(StealerLog)
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Инициализация драйвера (ленивая, один раз за процесс)
# ---------------------------------------------------------------------------

_driver: Any | None = None   # neo4j.AsyncDriver
_init_attempted: bool = False


def _get_driver() -> Any | None:
    """
    Возвращает синглтон AsyncDriver или None, если Neo4j недоступен.

    Флаг _init_attempted предотвращает повторные попытки подключения
    при каждом запросе когда сервер заведомо недоступен.
    """
    global _driver, _init_attempted
    if _driver is not None:
        return _driver
    if _init_attempted:
        return None

    _init_attempted = True
    uri = os.environ.get("NEO4J_URI", "")
    password = os.environ.get("NEO4J_PASSWORD", "changeme")

    if not uri:
        logger.info("[neo4j] NEO4J_URI не задан — Attack Path Graph отключён (опционально)")
        return None

    try:
        from neo4j import AsyncGraphDatabase  # type: ignore[import]
        _driver = AsyncGraphDatabase.driver(uri, auth=("neo4j", password))
        logger.info("[neo4j] Драйвер инициализирован: %s", uri)
    except Exception as exc:
        logger.warning("[neo4j] Не удалось инициализировать драйвер: %s", exc)
        _driver = None

    return _driver


# ---------------------------------------------------------------------------
# Создание constraints (вызывается при старте приложения)
# ---------------------------------------------------------------------------

async def ensure_constraints() -> None:
    """
    Создаёт уникальные индексы при старте.
    Безопасно при повторном вызове (IF NOT EXISTS).
    Молча игнорирует ошибки, если Neo4j недоступен.
    """
    driver = _get_driver()
    if driver is None:
        return

    constraints = [
        "CREATE CONSTRAINT domain_name IF NOT EXISTS "
        "FOR (d:Domain) REQUIRE d.name IS UNIQUE",

        "CREATE CONSTRAINT asset_fqdn IF NOT EXISTS "
        "FOR (a:Asset) REQUIRE a.fqdn IS UNIQUE",

        "CREATE CONSTRAINT cred_email IF NOT EXISTS "
        "FOR (c:CredentialLeak) REQUIRE c.email IS UNIQUE",
    ]

    try:
        async with driver.session() as session:
            for cypher in constraints:
                try:
                    await session.run(cypher)
                except Exception as exc:
                    # Некоторые версии не поддерживают IF NOT EXISTS — игнорируем
                    logger.debug("[neo4j] Constraint (пропущена): %s", exc)
        logger.info("[neo4j] Constraints проверены/созданы")
    except Exception as exc:
        logger.warning("[neo4j] ensure_constraints ошибка: %s", exc)


# ---------------------------------------------------------------------------
# Запись события в граф
# ---------------------------------------------------------------------------

async def upsert_event_to_graph(event: dict[str, Any]) -> bool:
    """
    Создаёт/обновляет ноды в графе на основе NormalizedEvent.

    Вызывается через asyncio.ensure_future из ingest.py — не блокирует ответ.
    При недоступном Neo4j возвращает False без исключения.

    Поддерживаемые event_type:
        subdomain, exposed_service, credential_leak, stealer_log, vulnerability
    """
    driver = _get_driver()
    if driver is None:
        return False

    event_type: str = event.get("event_type", "")
    domain: str = event.get("target_domain", "")
    payload: dict[str, Any] = event.get("payload") or {}
    severity: str = event.get("severity", "info")

    if not domain:
        return False

    try:
        async with driver.session() as session:
            # Корневой Domain — всегда создаём/обновляем
            await session.run(
                "MERGE (d:Domain {name: $name}) SET d.last_seen = datetime()",
                name=domain,
            )

            if event_type == "subdomain":
                fqdn: str = (
                    payload.get("subdomain")
                    or payload.get("fqdn")
                    or domain
                )
                ip: str = payload.get("ip") or ""
                await session.run(
                    """
                    MERGE (d:Domain {name: $domain})
                    MERGE (a:Asset {fqdn: $fqdn})
                    SET a.ip = $ip, a.last_seen = datetime()
                    MERGE (d)-[:HAS_SUBDOMAIN]->(a)
                    """,
                    domain=domain,
                    fqdn=fqdn,
                    ip=ip,
                )

            elif event_type == "exposed_service":
                port_num = payload.get("port")
                asset_ip: str = payload.get("ip") or ""
                if port_num is not None:
                    await session.run(
                        """
                        MERGE (a:Asset {fqdn: $fqdn})
                        SET a.last_seen = datetime()
                        MERGE (p:Port {number: $port, ip: $ip})
                        SET p.service = $service,
                            p.version = $version,
                            p.last_seen = datetime()
                        MERGE (a)-[:HAS_PORT]->(p)
                        """,
                        fqdn=domain,
                        port=int(port_num),
                        ip=asset_ip,
                        service=payload.get("service") or "",
                        version=payload.get("version") or "",
                    )

            elif event_type in ("credential_leak", "stealer_log"):
                login: str = payload.get("login") or payload.get("email") or ""
                if login:
                    await session.run(
                        """
                        MERGE (d:Domain {name: $domain})
                        MERGE (c:CredentialLeak {email: $email})
                        SET c.masked_password = $pwd, c.last_seen = datetime()
                        MERGE (d)-[:ASSOCIATED_WITH]->(c)
                        """,
                        domain=domain,
                        email=login,
                        pwd=payload.get("password_masked") or "***",
                    )
                    filename: str = payload.get("filename") or payload.get("source_file") or ""
                    if filename:
                        await session.run(
                            """
                            MERGE (c:CredentialLeak {email: $email})
                            MERGE (s:StealerLog {filename: $filename})
                            SET s.last_seen = datetime()
                            MERGE (c)-[:LEAKED_IN]->(s)
                            """,
                            email=login,
                            filename=filename,
                        )

            elif event_type == "vulnerability":
                vuln_name: str = (
                    payload.get("template_id")
                    or payload.get("title")
                    or "unknown"
                )
                await session.run(
                    """
                    MERGE (a:Asset {fqdn: $fqdn})
                    MERGE (v:Vulnerability {name: $name})
                    SET v.severity = $severity, v.last_seen = datetime()
                    MERGE (a)-[:HAS_VULN]->(v)
                    """,
                    fqdn=domain,
                    name=vuln_name,
                    severity=severity,
                )

        return True

    except Exception as exc:
        logger.debug("[neo4j] upsert_event_to_graph ошибка: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Поиск путей атаки
# ---------------------------------------------------------------------------

async def find_attack_paths(domain: str) -> list[dict[str, Any]]:
    """
    Ищет классические пути атаки для домена:
    ATTACKER → открытый порт/сервис + утёкшие учётные данные → Crown Jewel.

    Запросы сгруппированы по типу пути:
    1. Прямой доступ: Asset с открытым портом + CredentialLeak для того же Domain
    2. Уязвимый актив: Asset с критической уязвимостью + CredentialLeak

    Возвращает список dict с полями:
        asset, port, service, leaked_email, attack_type, risk, risk_score
    """
    driver = _get_driver()
    if driver is None:
        return []

    try:
        async with driver.session() as session:
            paths: list[dict[str, Any]] = []

            # --- Путь 1: открытый порт + утечка учётных данных ---
            result = await session.run(
                """
                MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(a:Asset)-[:HAS_PORT]->(p:Port)
                MATCH (d)-[:ASSOCIATED_WITH]->(c:CredentialLeak)
                WHERE p.service IS NOT NULL AND p.service <> ''
                RETURN
                    a.fqdn        AS asset,
                    p.number      AS port,
                    p.service     AS service,
                    c.email       AS leaked_email,
                    'direct_access' AS attack_type
                LIMIT 20
                """,
                domain=domain,
            )
            async for record in result:
                paths.append({
                    "asset":        record["asset"],
                    "port":         record["port"],
                    "service":      record["service"],
                    "leaked_email": record["leaked_email"],
                    "attack_type":  record["attack_type"],
                    "risk":         "Открытый порт + утечка учётных данных для того же домена",
                    "risk_score":   100,
                })

            # --- Путь 2: уязвимый актив (critical/high) + утечка учётных данных ---
            result2 = await session.run(
                """
                MATCH (d:Domain {name: $domain})-[:HAS_SUBDOMAIN]->(a:Asset)-[:HAS_VULN]->(v:Vulnerability)
                MATCH (d)-[:ASSOCIATED_WITH]->(c:CredentialLeak)
                WHERE v.severity IN ['critical', 'high']
                RETURN
                    a.fqdn         AS asset,
                    v.name         AS vuln,
                    v.severity     AS severity,
                    c.email        AS leaked_email,
                    'vuln_plus_cred' AS attack_type
                LIMIT 20
                """,
                domain=domain,
            )
            async for record in result2:
                paths.append({
                    "asset":        record["asset"],
                    "vuln":         record["vuln"],
                    "severity":     record["severity"],
                    "leaked_email": record["leaked_email"],
                    "attack_type":  record["attack_type"],
                    "risk":         f"Уязвимость {record['severity'].upper()} + утечка учётных данных",
                    "risk_score":   95 if record["severity"] == "critical" else 80,
                })

            return paths

    except Exception as exc:
        logger.debug("[neo4j] find_attack_paths ошибка: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Визуализация графа домена
# ---------------------------------------------------------------------------

async def get_domain_graph(domain: str) -> dict[str, Any]:
    """
    Возвращает весь граф домена в D3.js/Vis.js-совместимом формате:
        {"nodes": [...], "edges": [...]}

    Каждый node: {id, label, type, ...props}
    Каждый edge:  {source, target, label}
    """
    driver = _get_driver()
    if driver is None:
        return {"nodes": [], "edges": []}

    try:
        async with driver.session() as session:
            nodes: dict[str, dict[str, Any]] = {}
            edges: list[dict[str, Any]] = []

            # Забираем весь подграф одним Cypher-запросом
            result = await session.run(
                """
                MATCH path = (d:Domain {name: $domain})-[*1..4]-(leaf)
                UNWIND relationships(path) AS rel
                RETURN
                    startNode(rel) AS src,
                    endNode(rel)   AS dst,
                    type(rel)      AS rel_type,
                    labels(startNode(rel)) AS src_labels,
                    labels(endNode(rel))   AS dst_labels,
                    properties(startNode(rel)) AS src_props,
                    properties(endNode(rel))   AS dst_props,
                    id(startNode(rel)) AS src_id,
                    id(endNode(rel))   AS dst_id
                LIMIT 200
                """,
                domain=domain,
            )

            async for record in result:
                src_id = str(record["src_id"])
                dst_id = str(record["dst_id"])

                if src_id not in nodes:
                    nodes[src_id] = _build_node(
                        src_id,
                        record["src_labels"],
                        record["src_props"],
                    )
                if dst_id not in nodes:
                    nodes[dst_id] = _build_node(
                        dst_id,
                        record["dst_labels"],
                        record["dst_props"],
                    )

                edges.append({
                    "source": src_id,
                    "target": dst_id,
                    "label":  record["rel_type"],
                })

            return {
                "nodes": list(nodes.values()),
                "edges": edges,
            }

    except Exception as exc:
        logger.debug("[neo4j] get_domain_graph ошибка: %s", exc)
        return {"nodes": [], "edges": []}


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def _build_node(
    node_id: str,
    labels: list[str],
    props: dict[str, Any],
) -> dict[str, Any]:
    """Строит dict-представление ноды для клиентской визуализации."""
    node_type = labels[0] if labels else "Unknown"

    # Выбираем человекочитаемую метку для отображения
    label = (
        props.get("name")
        or props.get("fqdn")
        or props.get("email")
        or props.get("filename")
        or f"{node_type}:{node_id}"
    )

    # Для Port добавляем номер и сервис
    if node_type == "Port":
        port_num = props.get("number", "?")
        service = props.get("service", "")
        label = f"{port_num}/{service}" if service else str(port_num)

    return {
        "id":    node_id,
        "label": label,
        "type":  node_type,
        **{k: v for k, v in props.items() if k != "last_seen"},
    }


# ---------------------------------------------------------------------------
# Закрытие соединения (для graceful shutdown)
# ---------------------------------------------------------------------------

async def close_driver() -> None:
    """Закрывает Neo4j-драйвер при завершении приложения."""
    global _driver, _init_attempted
    if _driver is not None:
        try:
            await _driver.close()
        except Exception as exc:
            logger.debug("[neo4j] close_driver ошибка: %s", exc)
        finally:
            _driver = None
            _init_attempted = False
