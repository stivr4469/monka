"""
AI Risk Narrative — генерация executive summary через Claude API.
Использует prompt caching для экономии токенов.
"""
import logging
import os
from datetime import date
from typing import Any

logger = logging.getLogger(__name__)

# Проверяем наличие anthropic SDK при импорте модуля
try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
    logger.warning("anthropic SDK не установлен — будет использован статичный fallback")

_MODEL = "claude-haiku-4-5-20251001"  # Haiku для экономии, Sonnet для качества

SYSTEM_PROMPT = (
    "You are a cybersecurity risk analyst writing executive briefings for C-suite. "
    "Write in clear, non-technical language. Be concise (max 3 paragraphs). "
    "Focus on business impact, not technical details. "
    "Do not use jargon. Use bullet points sparingly."
)


def _build_user_prompt(
    domain: str,
    score: float,
    category_scores: dict[str, float],
    top_risks: list[dict[str, Any]],
    org_name: str,
) -> str:
    """Формирует user-промпт с данными о рисках."""
    net = category_scores.get("network_security", 100)
    dns = category_scores.get("dns_health", 100)
    app = category_scores.get("application_security", 100)
    cred = category_scores.get("credential_exposure", 100)
    dw = category_scores.get("dark_web_presence", 100)
    brand = category_scores.get("brand_safety", 100)

    risks_text = ""
    for i, risk in enumerate(top_risks[:5], start=1):
        event_type = risk.get("event_type", "unknown")
        severity = risk.get("severity", "unknown")
        description = risk.get("description", "")
        risks_text += f"  {i}. [{severity.upper()}] {event_type}: {description}\n"

    if not risks_text:
        risks_text = "  (нет активных событий)\n"

    return (
        f"Organization: {org_name}\n"
        f"Domain: {domain}\n"
        f"Current Security Score: {score:.0f}/100\n\n"
        f"Category Scores:\n"
        f"  Network Security: {net:.0f}/100\n"
        f"  DNS Health: {dns:.0f}/100\n"
        f"  Application Security: {app:.0f}/100\n"
        f"  Credential Exposure: {cred:.0f}/100\n"
        f"  Dark Web Presence: {dw:.0f}/100\n"
        f"  Brand Safety: {brand:.0f}/100\n\n"
        f"Top Risks:\n{risks_text}\n"
        f"Please write a brief executive summary of the security posture and key risks "
        f"for {org_name}, focusing on business impact and recommended priorities."
    )


def _static_narrative(
    domain: str,
    score: float,
    category_scores: dict[str, float],
    top_risks: list[dict[str, Any]],
    org_name: str,
) -> str:
    """Статичный fallback — шаблонный текст если API недоступен."""
    today = date.today().isoformat()

    # Определяем буквенную оценку
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Формируем список рисков
    risks_lines = []
    for risk in top_risks[:5]:
        event_type = risk.get("event_type", "unknown")
        severity = risk.get("severity", "unknown")
        description = risk.get("description", "")
        line = f"- [{severity.upper()}] {event_type}"
        if description:
            line += f": {description}"
        risks_lines.append(line)

    risks_text = "\n".join(risks_lines) if risks_lines else "- Активных угроз не обнаружено"

    # Рекомендации по score
    if score >= 75:
        action = "Maintain current security posture and continue monitoring."
    elif score >= 50:
        action = "Address identified medium and high severity findings promptly."
    else:
        action = "Immediate remediation of critical findings required. Escalate to security team."

    return (
        f"**{org_name} Security Report — {today}**\n\n"
        f"**Overall Score: {score:.0f}/100 (Grade: {grade})**\n\n"
        f"Key risks identified for `{domain}`:\n"
        f"{risks_text}\n\n"
        f"**Immediate actions recommended:** {action}"
    )


def generate_risk_narrative(
    domain: str,
    score: float,
    category_scores: dict[str, float],
    top_risks: list[dict[str, Any]],
    org_name: str = "your organization",
) -> str:
    """
    Генерирует executive summary рисков через Claude API.

    Возвращает markdown-текст для C-suite аудитории.
    Fallback: статичный шаблон если API недоступен или ключ не задан.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key or not _ANTHROPIC_AVAILABLE:
        return _static_narrative(domain, score, category_scores, top_risks, org_name)

    user_prompt = _build_user_prompt(domain, score, category_scores, top_risks, org_name)

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=_MODEL,
            max_tokens=512,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},  # кэшируем системный промпт
                }
            ],
            messages=[{"role": "user", "content": user_prompt}],
        )
        return response.content[0].text
    except Exception as exc:
        logger.warning("Ошибка вызова Claude API: %s — используем статичный fallback", exc)
        return _static_narrative(domain, score, category_scores, top_risks, org_name)
