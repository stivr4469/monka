"""
Генератор PDF-отчётов по безопасности (задача 8.E).

Два типа отчётов:
- Технический (generate_technical_report) — для инженеров ИБ.
- Executive (generate_executive_report)   — для руководства, без жаргона.

Зависимость: reportlab==4.2.2 (в requirements.txt).
"""

from __future__ import annotations

import io
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ─── Палитра ──────────────────────────────────────────────────────────────────

_COLOR_CRITICAL = colors.HexColor("#f85149")
_COLOR_HIGH     = colors.HexColor("#f0883e")
_COLOR_MEDIUM   = colors.HexColor("#e3b341")
_COLOR_LOW      = colors.HexColor("#3fb950")
_COLOR_INFO     = colors.HexColor("#58a6ff")
_COLOR_HEADER   = colors.HexColor("#161b22")
_COLOR_ACCENT   = colors.HexColor("#1f6feb")
_COLOR_TEXT     = colors.HexColor("#e6edf3")
_COLOR_MUTED    = colors.HexColor("#8b949e")
_COLOR_BG_ROW   = colors.HexColor("#0d1117")
_COLOR_BG_ALT   = colors.HexColor("#161b22")

_SEV_COLORS: dict[str, colors.HexColor] = {
    "critical": _COLOR_CRITICAL,
    "high":     _COLOR_HIGH,
    "medium":   _COLOR_MEDIUM,
    "low":      _COLOR_LOW,
    "info":     _COLOR_INFO,
}

# ─── Интерпретация score ──────────────────────────────────────────────────────

_SCORE_INTERPRETATIONS: dict[str, tuple[int, int, str, str]] = {
    # level: (min_score, max_score, label_ru, description_ru)
    "excellent": (80, 100,
                  "Отличная безопасность",
                  "Организация демонстрирует высокий уровень защиты. "
                  "Критических угроз не обнаружено."),
    "attention": (60, 79,
                  "Требует внимания",
                  "Выявлены уязвимости, которые необходимо устранить "
                  "в плановом порядке для поддержания надёжной защиты."),
    "problems":  (40, 59,
                  "Есть проблемы",
                  "Обнаружены значительные уязвимости. "
                  "Рекомендуется незамедлительная проверка и устранение рисков."),
    "critical":  (0, 39,
                  "Критическое состояние",
                  "Зафиксированы серьёзные угрозы безопасности, "
                  "требующие немедленного реагирования."),
}


def _score_interpretation(score: int) -> tuple[str, str, colors.HexColor]:
    """Возвращает (label, description, color) по числовому score."""
    for info in _SCORE_INTERPRETATIONS.values():
        min_s, max_s, label, desc = info
        if min_s <= score <= max_s:
            color = _COLOR_LOW if min_s >= 80 else (
                _COLOR_MEDIUM if min_s >= 60 else (
                    _COLOR_HIGH if min_s >= 40 else _COLOR_CRITICAL
                )
            )
            return label, desc, color
    return "Нет данных", "Оценка риска недоступна.", _COLOR_MUTED


# ─── Вспомогательные стили ────────────────────────────────────────────────────

def _build_styles() -> dict[str, ParagraphStyle]:
    """Возвращает словарь переиспользуемых стилей Paragraph."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontSize=20,
            textColor=_COLOR_TEXT,
            spaceAfter=6,
            alignment=TA_CENTER,
            fontName="Helvetica-Bold",
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle",
            parent=base["Normal"],
            fontSize=10,
            textColor=_COLOR_MUTED,
            spaceAfter=4,
            alignment=TA_CENTER,
            fontName="Helvetica",
        ),
        "section": ParagraphStyle(
            "SectionHeader",
            parent=base["Heading2"],
            fontSize=13,
            textColor=_COLOR_ACCENT,
            spaceBefore=14,
            spaceAfter=6,
            fontName="Helvetica-Bold",
        ),
        "body": ParagraphStyle(
            "BodyText",
            parent=base["Normal"],
            fontSize=9,
            textColor=_COLOR_TEXT,
            leading=14,
            spaceAfter=6,
            fontName="Helvetica",
        ),
        "score_label": ParagraphStyle(
            "ScoreLabel",
            parent=base["Normal"],
            fontSize=11,
            textColor=_COLOR_TEXT,
            fontName="Helvetica-Bold",
        ),
        "bullet": ParagraphStyle(
            "Bullet",
            parent=base["Normal"],
            fontSize=9,
            textColor=_COLOR_TEXT,
            leading=14,
            leftIndent=14,
            spaceAfter=3,
            fontName="Helvetica",
        ),
    }


def _hr() -> HRFlowable:
    return HRFlowable(
        width="100%",
        thickness=0.5,
        color=_COLOR_MUTED,
        spaceAfter=8,
        spaceBefore=2,
    )


def _doc_template(buf: io.BytesIO, title: str) -> SimpleDocTemplate:
    return SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title=title,
        creator="EASM Security Platform",
    )


def _now_str() -> str:
    """Строка текущего UTC-времени для подписи отчёта."""
    return datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")


# ─── Генераторы отчётов ───────────────────────────────────────────────────────

def generate_technical_report(
    org_name: str,
    domain: str,
    risk_score: int,
    events: list[dict[str, Any]],
) -> bytes:
    """
    Генерирует технический PDF-отчёт для инженеров ИБ.

    Содержимое:
    - Заголовок с доменом и датой.
    - Risk Score (крупно).
    - Таблица топ-10 событий: severity / event_type / detected_at / source_name.
    - Разбивка по категориям severity.

    Возвращает bytes готового PDF.
    """
    buf = io.BytesIO()
    doc = _doc_template(buf, f"Security Report — {domain}")
    styles = _build_styles()
    story: list[Any] = []

    # ── Заголовок ──────────────────────────────────────────────────────────────
    story.append(Paragraph(f"Security Report", styles["title"]))
    story.append(Paragraph(domain, ParagraphStyle(
        "DomainTitle",
        parent=styles["subtitle"],
        fontSize=13,
        textColor=_COLOR_ACCENT,
        fontName="Helvetica-Bold",
        spaceAfter=4,
    )))
    story.append(Paragraph(f"Организация: {org_name}", styles["subtitle"]))
    story.append(Paragraph(f"Сформирован: {_now_str()}", styles["subtitle"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(_hr())

    # ── Risk Score ─────────────────────────────────────────────────────────────
    story.append(Paragraph("Оценка риска", styles["section"]))

    score_label, score_desc, score_color = _score_interpretation(risk_score)
    score_big = ParagraphStyle(
        "ScoreBig",
        parent=styles["body"],
        fontSize=36,
        textColor=score_color,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    story.append(Paragraph(str(risk_score), score_big))
    story.append(Paragraph(score_label, ParagraphStyle(
        "ScoreLevel",
        parent=styles["subtitle"],
        fontSize=11,
        textColor=score_color,
        fontName="Helvetica-Bold",
    )))
    story.append(Spacer(1, 0.3 * cm))

    # ── Топ-10 событий ─────────────────────────────────────────────────────────
    story.append(_hr())
    story.append(Paragraph("Топ-10 событий по severity", styles["section"]))

    # Сортируем по тяжести и по дате
    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_events = sorted(
        events,
        key=lambda e: (_sev_order.get(str(e.get("severity", "info")).lower(), 5),
                       str(e.get("detected_at", ""))),
    )
    top10 = sorted_events[:10]

    if top10:
        col_widths = [2.5 * cm, 4.5 * cm, 4.0 * cm, 5.5 * cm]
        table_data: list[list[Any]] = [
            [
                Paragraph("<b>Severity</b>", styles["body"]),
                Paragraph("<b>Event Type</b>", styles["body"]),
                Paragraph("<b>Detected At</b>", styles["body"]),
                Paragraph("<b>Source</b>", styles["body"]),
            ]
        ]

        for ev in top10:
            sev = str(ev.get("severity", "info")).lower()
            sev_color = _SEV_COLORS.get(sev, _COLOR_INFO)
            detected = ev.get("detected_at", "")
            if isinstance(detected, datetime):
                detected = detected.strftime("%d.%m.%Y %H:%M")
            elif isinstance(detected, str) and detected:
                try:
                    dt = datetime.fromisoformat(detected.replace("Z", "+00:00"))
                    detected = dt.strftime("%d.%m.%Y %H:%M")
                except ValueError:
                    pass

            table_data.append([
                Paragraph(
                    f'<font color="#{sev_color.hexval()[2:]}"><b>{sev.upper()}</b></font>',
                    styles["body"],
                ),
                Paragraph(str(ev.get("event_type", "—")), styles["body"]),
                Paragraph(str(detected) if detected else "—", styles["body"]),
                Paragraph(str(ev.get("source_name", "—"))[:50], styles["body"]),
            ])

        tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0),  _COLOR_ACCENT),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_COLOR_BG_ROW, _COLOR_BG_ALT]),
            ("TEXTCOLOR",   (0, 1), (-1, -1), _COLOR_TEXT),
            ("GRID",        (0, 0), (-1, -1), 0.3, _COLOR_MUTED),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("LEFTPADDING",  (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING",   (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
        ]))
        story.append(tbl)
    else:
        story.append(Paragraph("Событий не обнаружено.", styles["body"]))

    # ── Разбивка по категориям ─────────────────────────────────────────────────
    story.append(Spacer(1, 0.4 * cm))
    story.append(_hr())
    story.append(Paragraph("Разбивка по уровням серьёзности", styles["section"]))

    severity_counts: Counter[str] = Counter(
        str(e.get("severity", "info")).lower() for e in events
    )
    sev_order = ["critical", "high", "medium", "low", "info"]
    total_events = sum(severity_counts.values())

    sev_table_data: list[list[Any]] = [
        [
            Paragraph("<b>Уровень</b>", styles["body"]),
            Paragraph("<b>Количество</b>", styles["body"]),
            Paragraph("<b>Доля</b>", styles["body"]),
        ]
    ]
    for sev in sev_order:
        count = severity_counts.get(sev, 0)
        pct = f"{count / total_events * 100:.1f}%" if total_events else "0%"
        sev_color = _SEV_COLORS.get(sev, _COLOR_INFO)
        sev_table_data.append([
            Paragraph(
                f'<font color="#{sev_color.hexval()[2:]}"><b>{sev.upper()}</b></font>',
                styles["body"],
            ),
            Paragraph(str(count), styles["body"]),
            Paragraph(pct, styles["body"]),
        ])

    sev_tbl = Table(sev_table_data, colWidths=[4 * cm, 3 * cm, 3 * cm], repeatRows=1)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  _COLOR_ACCENT),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_COLOR_BG_ROW, _COLOR_BG_ALT]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), _COLOR_TEXT),
        ("GRID",        (0, 0), (-1, -1), 0.3, _COLOR_MUTED),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    story.append(sev_tbl)
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(f"Всего событий: {total_events}", styles["body"]))

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr())
    story.append(Paragraph(
        "EASM Security Platform — Технический отчёт",
        ParagraphStyle("Footer", parent=styles["subtitle"], fontSize=7),
    ))

    doc.build(story)
    return buf.getvalue()


def generate_executive_report(
    org_name: str,
    domain: str,
    risk_score: int,
    events: list[dict[str, Any]],
) -> bytes:
    """
    Генерирует Executive PDF-отчёт для руководства.

    Содержимое:
    - Заголовок с названием организации.
    - Краткое резюме состояния безопасности (без жаргона).
    - Risk Score с интерпретацией.
    - Топ-3 критических риска простым языком.
    - Раздел "Рекомендации".

    Возвращает bytes готового PDF.
    """
    buf = io.BytesIO()
    doc = _doc_template(buf, f"Executive Security Report — {org_name}")
    styles = _build_styles()
    story: list[Any] = []

    # ── Заголовок ──────────────────────────────────────────────────────────────
    story.append(Paragraph("Executive Security Report", styles["title"]))
    story.append(Paragraph(org_name, ParagraphStyle(
        "ExecOrgTitle",
        parent=styles["subtitle"],
        fontSize=13,
        textColor=_COLOR_ACCENT,
        fontName="Helvetica-Bold",
        spaceAfter=4,
    )))
    story.append(Paragraph(f"Домен: {domain}", styles["subtitle"]))
    story.append(Paragraph(f"Дата подготовки: {_now_str()}", styles["subtitle"]))
    story.append(Spacer(1, 0.3 * cm))
    story.append(_hr())

    # ── Краткое резюме ─────────────────────────────────────────────────────────
    story.append(Paragraph("Общая оценка состояния безопасности", styles["section"]))

    score_label, score_desc, score_color = _score_interpretation(risk_score)
    severity_counts: Counter[str] = Counter(
        str(e.get("severity", "info")).lower() for e in events
    )
    critical_count = severity_counts.get("critical", 0)
    high_count     = severity_counts.get("high", 0)
    total_count    = sum(severity_counts.values())

    # Формируем краткое резюме на основе данных
    if critical_count > 0:
        summary = (
            f"В результате анализа инфраструктуры организации <b>{org_name}</b> "
            f"выявлены <b>{critical_count} критических</b> угроз, "
            f"требующих немедленного реагирования. "
            f"Уровень защищённости оценивается как <b>{score_label.lower()}</b>. "
            f"Рекомендуется незамедлительно эскалировать вопрос к команде ИБ."
        )
    elif high_count > 0:
        summary = (
            f"Инфраструктура организации <b>{org_name}</b> находится "
            f"под умеренным риском. Обнаружено <b>{high_count}</b> угроз высокого "
            f"уровня, которые необходимо устранить в ближайшее время. "
            f"Общий уровень защищённости: <b>{score_label.lower()}</b>."
        )
    elif total_count > 0:
        summary = (
            f"Инфраструктура организации <b>{org_name}</b> в целом защищена. "
            f"Выявленные угрозы ({total_count}) носят низкий или информационный характер. "
            f"Уровень защищённости: <b>{score_label.lower()}</b>."
        )
    else:
        summary = (
            f"По результатам анализа инфраструктура организации <b>{org_name}</b> "
            f"не содержит обнаруженных угроз безопасности. "
            f"Уровень защищённости: <b>{score_label.lower()}</b>."
        )

    story.append(Paragraph(summary, styles["body"]))
    story.append(Spacer(1, 0.3 * cm))

    # ── Risk Score с интерпретацией ────────────────────────────────────────────
    story.append(_hr())
    story.append(Paragraph("Индекс защищённости (Risk Score)", styles["section"]))

    score_big = ParagraphStyle(
        "ExecScoreBig",
        parent=styles["body"],
        fontSize=42,
        textColor=score_color,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
        spaceAfter=4,
    )
    story.append(Paragraph(str(risk_score), score_big))
    story.append(Paragraph(score_label, ParagraphStyle(
        "ExecScoreLevel",
        parent=styles["subtitle"],
        fontSize=12,
        textColor=score_color,
        fontName="Helvetica-Bold",
        spaceAfter=6,
    )))
    story.append(Paragraph(score_desc, styles["body"]))
    story.append(Spacer(1, 0.2 * cm))

    # Шкала интерпретации
    scale_data = [
        ["80–100", "Отличная безопасность", "Угроз практически нет"],
        ["60–79",  "Требует внимания",       "Есть задачи для плановой работы"],
        ["40–59",  "Есть проблемы",          "Нужны меры в ближайшее время"],
        ["0–39",   "Критично",               "Требует немедленного реагирования"],
    ]
    scale_colors = [_COLOR_LOW, _COLOR_MEDIUM, _COLOR_HIGH, _COLOR_CRITICAL]
    scale_table_data = [[
        Paragraph("<b>Диапазон</b>", styles["body"]),
        Paragraph("<b>Уровень</b>", styles["body"]),
        Paragraph("<b>Значение</b>", styles["body"]),
    ]]
    for (rng, lvl, meaning), clr in zip(scale_data, scale_colors):
        is_current = any(
            int(rng.split("–")[0]) <= risk_score <= int(rng.split("–")[1])
            for _ in [None]
        )
        row_bg = clr if is_current else None
        scale_table_data.append([
            Paragraph(f'<font color="#{clr.hexval()[2:]}">{rng}</font>', styles["body"]),
            Paragraph(f'<font color="#{clr.hexval()[2:]}">{lvl}</font>', styles["body"]),
            Paragraph(meaning, styles["body"]),
        ])

    scale_tbl = Table(
        scale_table_data,
        colWidths=[2.5 * cm, 4.5 * cm, 9.5 * cm],
        repeatRows=1,
    )
    scale_tbl.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  _COLOR_ACCENT),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [_COLOR_BG_ROW, _COLOR_BG_ALT]),
        ("TEXTCOLOR",   (0, 1), (-1, -1), _COLOR_TEXT),
        ("GRID",        (0, 0), (-1, -1), 0.3, _COLOR_MUTED),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    story.append(scale_tbl)

    # ── Топ-3 критических риска ────────────────────────────────────────────────
    story.append(Spacer(1, 0.3 * cm))
    story.append(_hr())
    story.append(Paragraph("Ключевые риски", styles["section"]))

    # Берём критические и high события, форматируем человекочитаемо
    priority_events = [
        e for e in events
        if str(e.get("severity", "")).lower() in ("critical", "high")
    ]
    # Сортируем: critical первые, затем high
    priority_events.sort(
        key=lambda e: (0 if str(e.get("severity", "")).lower() == "critical" else 1,
                       str(e.get("detected_at", "")))
    )
    top3 = priority_events[:3]

    if top3:
        for i, ev in enumerate(top3, 1):
            sev = str(ev.get("severity", "info")).lower()
            sev_color = _SEV_COLORS.get(sev, _COLOR_INFO)
            etype = str(ev.get("event_type", "неизвестный тип"))

            # Человекочитаемое описание типа события
            human_descriptions = {
                "subdomain":        "Обнаружен публично доступный поддомен",
                "vulnerability":    "Выявлена уязвимость в инфраструктуре",
                "secret_leak":      "Обнаружена утечка ключей или паролей",
                "exposed_service":  "Незащищённый сервис доступен из интернета",
                "stealer_log":      "Данные организации обнаружены в краже",
                "github_leak":      "Конфиденциальные данные попали на GitHub",
                "paste_leak":       "Данные опубликованы на публичном ресурсе",
                "darknet_mention":  "Упоминание организации в даркнете",
                "credential_leak":  "Утечка учётных данных сотрудников",
            }
            human_desc = human_descriptions.get(etype, f"Угроза типа «{etype}»")
            source = str(ev.get("source_name", "внешний источник"))[:40]

            story.append(Paragraph(
                f'<font color="#{sev_color.hexval()[2:]}"><b>Риск {i}. {human_desc}</b></font>',
                styles["score_label"],
            ))
            story.append(Paragraph(
                f"Источник: {source}. Уровень критичности: {sev.upper()}.",
                styles["bullet"],
            ))
            story.append(Spacer(1, 0.15 * cm))
    else:
        story.append(Paragraph(
            "Критических и высоких рисков не обнаружено.",
            styles["body"],
        ))

    # ── Рекомендации ──────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.2 * cm))
    story.append(_hr())
    story.append(Paragraph("Рекомендации", styles["section"]))

    # Динамически формируем рекомендации на основе типов событий
    found_types = {str(e.get("event_type", "")).lower() for e in events}
    recommendations: list[str] = []

    if "critical" in {str(e.get("severity", "")).lower() for e in events}:
        recommendations.append(
            "Немедленно привлечь команду информационной безопасности "
            "для устранения критических угроз."
        )
    if any(t in found_types for t in ("secret_leak", "credential_leak", "github_leak")):
        recommendations.append(
            "Провести аудит и ротацию всех скомпрометированных "
            "ключей доступа, паролей и токенов."
        )
    if any(t in found_types for t in ("stealer_log", "paste_leak")):
        recommendations.append(
            "Уведомить сотрудников, чьи учётные данные могли быть "
            "скомпрометированы, и обязать их сменить пароли."
        )
    if any(t in found_types for t in ("exposed_service", "subdomain")):
        recommendations.append(
            "Провести инвентаризацию публично доступных сервисов "
            "и закрыть несанкционированные точки доступа."
        )
    if "darknet_mention" in found_types:
        recommendations.append(
            "Усилить мониторинг активности в даркнете и провести "
            "расследование источника утечки данных."
        )

    # Базовые рекомендации если специфических нет
    if len(recommendations) < 3:
        base_recs = [
            "Внедрить регулярное сканирование инфраструктуры (не реже 1 раза в неделю).",
            "Обеспечить двухфакторную аутентификацию для всех административных аккаунтов.",
            "Организовать процесс управления уязвимостями с SLA на устранение.",
            "Провести обучение сотрудников по вопросам информационной безопасности.",
        ]
        for rec in base_recs:
            if len(recommendations) >= 5:
                break
            if rec not in recommendations:
                recommendations.append(rec)

    for i, rec in enumerate(recommendations[:5], 1):
        story.append(Paragraph(f"{i}. {rec}", styles["bullet"]))

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr())
    story.append(Paragraph(
        "EASM Security Platform — Executive Report — Конфиденциально",
        ParagraphStyle("ExecFooter", parent=styles["subtitle"], fontSize=7),
    ))

    doc.build(story)
    return buf.getvalue()
