/**
 * EASM Security Dashboard — app.js
 * Vanilla JS ES6+, без фреймворков.
 */

'use strict';

// ─────────────────────────────────────────────
// Константы
// ─────────────────────────────────────────────

const PAGE_SIZE       = 20;  // строк на страницу в Events
const REFRESH_INTERVAL = 30; // секунд авто-обновления Dashboard

// ─────────────────────────────────────────────
// Управление темой — Dark/Light Mode
// ─────────────────────────────────────────────

const Theme = {
  STORAGE_KEY: 'easm_theme',

  /** Применяет тему и обновляет иконку в хедере */
  apply(mode) {
    document.documentElement.setAttribute('data-theme', mode);
    localStorage.setItem(this.STORAGE_KEY, mode);
    const btn = document.getElementById('theme-toggle-btn');
    if (btn) btn.textContent = mode === 'light' ? '🌙' : '☀️';
  },

  /** Переключить между dark и light */
  toggle() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    this.apply(current === 'dark' ? 'light' : 'dark');
  },

  /** Инициализация — читаем из localStorage, по умолчанию dark */
  init() {
    const saved = localStorage.getItem(this.STORAGE_KEY) || 'dark';
    this.apply(saved);
  },
};

// ─────────────────────────────────────────────
// Класс API — все HTTP-запросы к бэкенду
// ─────────────────────────────────────────────

class API {
  /** Читает JWT из localStorage */
  static getToken() {
    return localStorage.getItem('easm_token');
  }

  /** Сохраняет JWT в localStorage */
  static setToken(token) {
    localStorage.setItem('easm_token', token);
  }

  /** Удаляет токен при логауте */
  static clearToken() {
    localStorage.removeItem('easm_token');
  }

  /**
   * Базовый метод запроса. При 401 — редирект на страницу логина.
   * @param {string} path  — относительный путь, например '/api/v1/events/'
   * @param {RequestInit} opts — стандартные fetch-опции
   */
  static async request(path, opts = {}) {
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    };

    const res = await fetch(path, { ...opts, headers });

    if (res.status === 401) {
      this.clearToken();
      window.location.href = '/login.html';
      return null;
    }

    return res;
  }

  /** Логин — POST /api/v1/auth/token (form-data, OAuth2PasswordRequestForm) */
  static async login(email, password) {
    const body = new URLSearchParams({ username: email, password });
    const res = await fetch('/api/v1/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    const data = await res.json();
    this.setToken(data.access_token);
    return data;
  }

  /** GET /api/v1/events/stats */
  static async getStats(domain = null) {
    const params = domain ? `?domain=${encodeURIComponent(domain)}` : '';
    const res = await this.request(`/api/v1/events/stats${params}`);
    if (!res || !res.ok) throw new Error(`Ошибка stats: ${res?.status}`);
    return res.json();
  }

  /**
   * GET /api/v1/events/
   * @param {{ domain?, severity?, event_type?, limit?, offset? }} filters
   */
  static async getEvents(filters = {}) {
    const params = new URLSearchParams();
    if (filters.domain)     params.set('domain', filters.domain);
    if (filters.severity)   params.set('severity', filters.severity);
    if (filters.event_type) params.set('event_type', filters.event_type);
    if (filters.limit)      params.set('limit', String(filters.limit || 100));
    if (filters.before)     params.set('before', filters.before);
    const qs = params.toString() ? `?${params}` : '';
    const res = await this.request(`/api/v1/events/${qs}`);
    if (!res || !res.ok) throw new Error(`Ошибка events: ${res?.status}`);
    const data = await res.json();
    // API возвращает {items: [...], next_before: "..."} — нормализуем в массив
    return Array.isArray(data) ? data : (data.items || []);
  }

  /** GET /api/v1/assets/ */
  static async getAssets() {
    const res = await this.request('/api/v1/assets/');
    if (!res || !res.ok) throw new Error(`Ошибка assets: ${res?.status}`);
    return res.json();
  }

  /**
   * POST /api/v1/assets/
   * @param {{ domain: string, description?: string }} body
   */
  static async createAsset(body) {
    const res = await this.request('/api/v1/assets/', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** DELETE /api/v1/assets/{id} */
  static async deleteAsset(id) {
    const res = await this.request(`/api/v1/assets/${id}`, { method: 'DELETE' });
    if (!res || (res.status !== 204 && !res.ok)) {
      throw new Error(`HTTP ${res?.status}`);
    }
  }

  /** POST /api/v1/schedule/asset/{id} — ручной запуск сканирования */
  static async scanAsset(id) {
    const res = await this.request(`/api/v1/schedule/asset/${id}`, { method: 'POST' });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /**
   * Скачивает PDF-отчёт через временный <a>-элемент.
   * @param {string} assetId
   * @param {'technical'|'executive'} type
   * @param {string} domain — для имени файла
   */
  static async downloadReport(assetId, type = 'technical', domain = 'report') {
    const endpoint = type === 'executive'
      ? `/api/v1/assets/${assetId}/executive-report.pdf`
      : `/api/v1/assets/${assetId}/report.pdf`;

    const token = this.getToken();
    const res = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) {
      this.clearToken();
      window.location.href = '/login.html';
      return;
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const safeDomain = domain.replace(/[^a-zA-Z0-9._-]/g, '_');
    a.href     = url;
    a.download = type === 'executive'
      ? `${safeDomain}_executive_report.pdf`
      : `${safeDomain}_security_report.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * GET /api/v1/assets/{id}/risk-score
   * Возвращает { score: number } или 404 → возвращаем null
   */
  static async getRiskScore(assetId) {
    try {
      const res = await this.request(`/api/v1/assets/${assetId}/risk-score`);
      if (!res || res.status === 404) return null;
      if (!res.ok) return null;
      return res.json();
    } catch {
      return null;
    }
  }

  /** GET /api/v1/alerts/ */
  static async getAlerts() {
    const res = await this.request('/api/v1/alerts/');
    if (!res || !res.ok) throw new Error(`Ошибка alerts: ${res?.status}`);
    return res.json();
  }

  /**
   * POST /api/v1/alerts/
   * @param {{ name, target_domain?, min_severity, telegram_chat_id, event_types? }} body
   */
  static async createAlert(body) {
    const res = await this.request('/api/v1/alerts/', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** DELETE /api/v1/alerts/{id} */
  static async deleteAlert(id) {
    const res = await this.request(`/api/v1/alerts/${id}`, { method: 'DELETE' });
    if (!res || (res.status !== 204 && !res.ok)) {
      throw new Error(`HTTP ${res?.status}`);
    }
  }

  /** POST /api/v1/alerts/test/{id} */
  static async testAlert(id) {
    const res = await this.request(`/api/v1/alerts/test/${id}`, { method: 'POST' });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /**
   * Запуск скана нужного модуля.
   * module: 'subfinder' | 'github' | 'paste'
   */
  static async startScan(module, domain) {
    const paths = {
      subfinder: '/api/v1/assets/',
      github:    '/api/v1/scan/github',
      paste:     '/api/v1/scan/paste',
    };
    if (module === 'subfinder') {
      return this.createAsset({ domain });
    }
    const path = paths[module];
    if (!path) throw new Error(`Неизвестный модуль: ${module}`);
    const res = await this.request(path, {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/hardening */
  static async scanHardening(domain) {
    const res = await this.request('/api/v1/scan/hardening', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/phishing */
  static async scanPhishing(domain) {
    const res = await this.request('/api/v1/scan/phishing', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/darknet */
  static async scanDarknet(domain) {
    const res = await this.request('/api/v1/scan/darknet', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/ports */
  static async scanPorts(domain) {
    const res = await this.request('/api/v1/scan/ports', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/s3 */
  static async scanS3(domain) {
    const res = await this.request('/api/v1/scan/s3', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /**
   * POST /api/v1/scan/cookies
   * Пассивная проверка живых сессий из стилер-лога (задача 9.C).
   * @param {string} domain
   * @param {string|null} [stealerLogId]
   */
  static async scanCookies(domain, stealerLogId = null) {
    const body = { domain };
    if (stealerLogId) body.stealer_log_id = stealerLogId;
    const res = await this.request('/api/v1/scan/cookies', {
      method: 'POST',
      body: JSON.stringify(body),
    });
    if (!res) return null;
    if (res.status === 404) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Стилер-архивы не найдены');
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/takeover */
  static async scanTakeover(domain) {
    const res = await this.request('/api/v1/scan/takeover', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /** POST /api/v1/scan/tls */
  static async scanTls(domain) {
    const res = await this.request('/api/v1/scan/tls', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    return res.json();
  }

  /**
   * GET /api/v1/billing/plan
   * Возвращает информацию о тарифном плане или null при ошибке (не бросает).
   * @returns {Promise<{plan:string,plan_label:string,domain_limit:number,domains_used:number,domains_remaining:number}|null>}
   */
  static async getBillingPlan() {
    try {
      const res = await this.request('/api/v1/billing/plan');
      if (!res || !res.ok) return null;
      return res.json();
    } catch {
      return null;
    }
  }
}

// ─────────────────────────────────────────────
// Toast-уведомления
// ─────────────────────────────────────────────

const Toast = {
  container: null,

  _init() {
    if (!this.container) {
      this.container = document.getElementById('toast-container');
    }
  },

  /**
   * Показать toast-уведомление.
   * @param {'success'|'error'|'info'|'warning'} type
   * @param {string} title
   * @param {string} [msg]
   */
  show(type, title, msg = '') {
    this._init();
    const icons = {
      success: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M5 8l2 2 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`,
      error:   `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M8 5v3M8 10.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
      info:    `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="7" stroke="currentColor" stroke-width="1.5"/><path d="M8 7v4M8 5.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
      warning: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 2L14 13H2L8 2z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M8 6v3M8 10.5v.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    };

    const colorMap = {
      success: 'var(--success)',
      error:   'var(--sev-critical)',
      info:    'var(--accent)',
      warning: 'var(--sev-high)',
    };

    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `
      <span class="toast-icon" style="color:${colorMap[type]}">${icons[type] || ''}</span>
      <div class="toast-content">
        <div class="toast-title">${escHtml(title)}</div>
        ${msg ? `<div class="toast-msg">${escHtml(msg)}</div>` : ''}
      </div>`;

    this.container.appendChild(el);

    // Авто-скрытие через 4 секунды
    setTimeout(() => {
      el.classList.add('hiding');
      setTimeout(() => el.remove(), 250);
    }, 4000);
  },
};

// ─────────────────────────────────────────────
// Утилиты
// ─────────────────────────────────────────────

/** Экранирование HTML для предотвращения XSS */
function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = String(str ?? '');
  return div.innerHTML;
}

/** Форматирование ISO-даты в удобочитаемый вид */
function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString('ru-RU', {
      day: '2-digit', month: '2-digit', year: '2-digit',
      hour: '2-digit', minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

/** Короткий формат времени — ЧЧ:ММ:СС */
function fmtTime(date) {
  return date.toLocaleTimeString('ru-RU', {
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

/** Сокращение длинного текста */
function truncate(str, len = 40) {
  if (!str) return '—';
  return str.length > len ? str.slice(0, len) + '…' : str;
}

/** Установка кнопки в состояние загрузки */
function setLoading(btn, loading) {
  if (loading) {
    btn.disabled = true;
    btn._origHtml = btn.innerHTML;
    const label = btn.textContent.trim();
    btn.innerHTML = `<span class="spinner"></span>${label ? ' Загрузка…' : ''}`;
    btn.classList.add('loading');
  } else {
    btn.disabled = false;
    btn.innerHTML = btn._origHtml || btn.innerHTML;
    btn.classList.remove('loading');
  }
}

/** Severity badge HTML */
function severityBadge(sev) {
  const s = (sev || 'info').toLowerCase();
  const labels = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
  return `<span class="badge badge-${s}">${labels[s] || escHtml(sev)}</span>`;
}

/** Красивый JSON */
function prettyJson(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

/** Пустой state HTML */
function emptyStateHtml(text) {
  return `
    <div class="empty-state">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
        <circle cx="12" cy="12" r="10"/>
        <path d="M12 8v4M12 16h.01" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <h3>${escHtml(text)}</h3>
    </div>`;
}

// ─────────────────────────────────────────────
// Модальное окно — утилиты
// ─────────────────────────────────────────────

const Modal = {
  open(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('open');
  },
  close(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('open');
  },
  /** Закрытие по клику на backdrop */
  bindBackdrop(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener('click', (e) => {
      if (e.target === el) this.close(id);
    });
  },
};

// ─────────────────────────────────────────────
// Состояние приложения
// ─────────────────────────────────────────────

const State = {
  // Events pagination
  eventsPage: 1,
  eventsTotal: 0,
  eventsFilters: { severity: '', event_type: '', domain: '' },
  eventsData: [],

  // Последнее время обновления событий
  eventsLastUpdated: null,

  // Кэш данных events для сравнения (поиск новых critical)
  eventsCriticalIds: new Set(),

  // Assets
  assetsData: [],

  // Alerts
  alertsData: [],

  // Dashboard refresh timer
  refreshTimer:    null,
  refreshCountdown: REFRESH_INTERVAL,

  // Polling events (остановка когда вкладка скрыта)
  eventsPollingTimer: null,
};

// ─────────────────────────────────────────────
// Risk Score виджет
// ─────────────────────────────────────────────

/**
 * Определяет цвет по значению risk score.
 * 0-30 = зелёный, 31-60 = жёлтый, 61-80 = оранжевый, 81-100 = красный
 */
function riskScoreColor(score) {
  if (score <= 30)  return '#3fb950';
  if (score <= 60)  return '#e3b341';
  if (score <= 80)  return '#f0883e';
  return '#f85149';
}

/**
 * Анимирует круговой индикатор Risk Score.
 * @param {number|null} score — число 0-100 или null (N/A)
 */
function renderRiskScore(score) {
  const widget = document.getElementById('risk-score-widget');
  if (!widget) return;

  const fill  = widget.querySelector('.risk-dial-fill');
  const value = widget.querySelector('.risk-dial-value');
  const desc  = widget.querySelector('.risk-score-desc');

  if (score === null || score === undefined) {
    if (fill)  fill.style.strokeDashoffset = '201';
    if (value) value.textContent = 'N/A';
    if (desc)  desc.textContent  = 'Нет данных о риске';
    if (fill)  fill.style.stroke = 'var(--text-muted)';
    return;
  }

  const clamped  = Math.max(0, Math.min(100, score));
  const color    = riskScoreColor(clamped);
  const offset   = 201 - (201 * clamped / 100); // stroke-dashoffset

  // Устанавливаем цвет сразу, offset — через requestAnimationFrame для анимации
  if (fill)  fill.style.stroke = color;
  if (value) value.style.color = color;

  requestAnimationFrame(() => {
    if (fill) fill.style.strokeDashoffset = String(offset);
  });

  if (value) value.textContent = clamped;

  const labels = ['Низкий', 'Средний', 'Высокий', 'Критический'];
  const idx = clamped <= 30 ? 0 : clamped <= 60 ? 1 : clamped <= 80 ? 2 : 3;
  if (desc) desc.textContent = `Уровень риска: ${labels[idx]}`;
}

// ─────────────────────────────────────────────
// TAB: Dashboard
// ─────────────────────────────────────────────

async function renderDashboard() {
  try {
    const stats = await API.getStats();
    renderStats(stats);

    // Последние события для таблицы
    const events = await API.getEvents({ limit: 10 });
    renderRecentEvents(events);

    // Если есть активы — берём risk score первого
    if (State.assetsData && State.assetsData.length > 0) {
      const data = await API.getRiskScore(State.assetsData[0].id);
      renderRiskScore(data ? data.score : null);
    } else {
      renderRiskScore(null);
    }
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки', e.message);
  }
}

function renderStats(stats) {
  const total  = stats.total || 0;
  const bySev  = stats.by_severity || {};
  const byType = stats.by_type || {};

  // Карточки
  document.getElementById('stat-total').textContent    = total.toLocaleString('ru');
  document.getElementById('stat-critical').textContent = (bySev.critical || 0).toLocaleString('ru');
  document.getElementById('stat-high').textContent     = (bySev.high || 0).toLocaleString('ru');
  document.getElementById('stat-medium').textContent   = (bySev.medium || 0).toLocaleString('ru');

  // Bar chart по типам событий
  const chartEl = document.getElementById('events-type-chart');
  const sorted  = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  const maxVal  = sorted[0]?.[1] || 1;

  if (!sorted.length) {
    chartEl.innerHTML = emptyStateHtml('Нет данных о типах событий');
    return;
  }

  chartEl.innerHTML = sorted.map(([type, count]) => {
    const pct = Math.max(2, Math.round((count / maxVal) * 100));
    return `
      <div class="bar-row">
        <span class="bar-label" title="${escHtml(type)}">${escHtml(type)}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${pct}%"></div>
        </div>
        <span class="bar-count">${count.toLocaleString('ru')}</span>
      </div>`;
  }).join('');

  // Severity chart (обновляем если элемент есть)
  const sevChart = document.getElementById('severity-chart');
  if (sevChart) {
    const order  = ['critical', 'high', 'medium', 'low', 'info'];
    const colors = {
      critical: 'var(--sev-critical)',
      high:     'var(--sev-high)',
      medium:   'var(--sev-medium)',
      low:      'var(--sev-low)',
      info:     'var(--sev-info)',
    };
    const entries = order
      .map(k => [k, bySev[k] || 0])
      .filter(p => p[1] > 0);

    if (!entries.length) {
      sevChart.innerHTML = emptyStateHtml('Нет данных');
    } else {
      const maxSev = entries[0][1];
      sevChart.innerHTML = entries.map(([sev, count]) => {
        const pct   = Math.max(2, Math.round((count / maxSev) * 100));
        const label = sev.charAt(0).toUpperCase() + sev.slice(1);
        return `<div class="bar-row">
          <span class="bar-label">${label}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:${pct}%;background:${colors[sev]}"></div>
          </div>
          <span class="bar-count">${count.toLocaleString('ru')}</span>
        </div>`;
      }).join('');
    }
  }
}

function renderRecentEvents(events) {
  const tbody = document.getElementById('recent-events-tbody');
  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('Событий пока нет')}</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map(ev => {
    const isCritical = (ev.severity || '').toLowerCase() === 'critical';
    return `
    <tr data-id="${escHtml(ev.id)}"
        class="${isCritical ? 'row-critical' : ''}"
        onclick="toggleEventRow(this)">
      <td>${severityBadge(ev.severity)}</td>
      <td><code style="font-size:.8125rem">${escHtml(ev.event_type)}</code></td>
      <td><span class="domain-tag">${escHtml(ev.target_domain)}</span></td>
      <td>${escHtml(truncate(ev.source_name, 28))}</td>
      <td style="color:var(--text-muted);font-size:.8125rem">${fmtDate(ev.detected_at)}</td>
    </tr>
    <tr class="row-detail" id="detail-${escHtml(ev.id)}">
      <td colspan="5">
        <strong style="color:var(--text-2);font-size:.8125rem">Payload:</strong>
        <pre class="json-pre">${escHtml(prettyJson(ev.payload))}</pre>
      </td>
    </tr>`;
  }).join('');
}

/** Раскрыть/закрыть строку таблицы с payload */
function toggleEventRow(tr) {
  const id = tr.dataset.id;
  const detailRow = document.getElementById(`detail-${id}`);
  if (!detailRow) return;
  detailRow.classList.toggle('open');
}

// ─────────────────────────────────────────────
// Авто-обновление Dashboard
// ─────────────────────────────────────────────

function startDashboardRefresh() {
  stopDashboardRefresh();
  State.refreshCountdown = REFRESH_INTERVAL;
  _syncRefreshUI();

  State.refreshTimer = setInterval(() => {
    // Не обновляем когда вкладка скрыта
    if (document.hidden) return;

    State.refreshCountdown--;
    _syncRefreshUI();

    if (State.refreshCountdown <= 0) {
      State.refreshCountdown = REFRESH_INTERVAL;
      renderDashboard();
    }
  }, 1000);
}

function stopDashboardRefresh() {
  if (State.refreshTimer) {
    clearInterval(State.refreshTimer);
    State.refreshTimer = null;
  }
}

/** Обновляет все счётчики countdown */
function updateRefreshCounter() {
  _syncRefreshUI();
}

function _syncRefreshUI() {
  // Счётчик в хедере
  const cnt = document.getElementById('refresh-count');
  if (cnt) cnt.textContent = State.refreshCountdown;

  // Счётчик в footer дашборда
  const lbl = document.getElementById('refresh-label');
  if (lbl) lbl.textContent = State.refreshCountdown;

  // Индикатор в хедере — показываем только на дашборде
  const indicator = document.getElementById('refresh-indicator');
  if (indicator) {
    const dashActive = document.getElementById('tab-dashboard')?.classList.contains('active');
    indicator.style.display = dashActive ? 'flex' : 'none';
  }
}

// ─────────────────────────────────────────────
// TAB: Assets
// ─────────────────────────────────────────────

async function renderAssets() {
  const container = document.getElementById('assets-container');
  container.innerHTML = `<div class="loading-skeleton skeleton-line" style="height:80px"></div>`;
  try {
    const assets = await API.getAssets();
    State.assetsData = assets;
    buildAssetsGrid(assets);
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки активов', e.message);
    container.innerHTML = emptyStateHtml('Не удалось загрузить активы');
  }
}

function buildAssetsGrid(assets) {
  const container = document.getElementById('assets-container');
  if (!assets.length) {
    container.innerHTML = emptyStateHtml('Активов пока нет. Добавьте первый домен.');
    return;
  }
  container.innerHTML = `
    <div class="assets-grid">
      ${assets.map(a => assetCardHtml(a)).join('')}
    </div>`;
}

function assetCardHtml(a) {
  const statusBadge = a.is_active
    ? `<span class="badge badge-success">Active</span>`
    : `<span class="badge badge-danger">Inactive</span>`;

  return `
    <div class="asset-card" id="asset-${escHtml(a.id)}">
      <div class="asset-card-header">
        <div>
          <div class="asset-domain">${escHtml(a.domain)}</div>
          ${a.description ? `<div class="asset-desc">${escHtml(truncate(a.description, 60))}</div>` : ''}
        </div>
        ${statusBadge}
      </div>
      <div class="asset-meta">
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
          <circle cx="6" cy="6" r="5" stroke="currentColor" stroke-width="1.2"/>
          <path d="M6 3.5V6l1.5 1.5" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/>
        </svg>
        ID: <code style="font-size:.7rem">${escHtml(a.id.slice(0, 8))}…</code>
      </div>
      <div class="asset-actions">
        <button class="btn btn-primary btn-sm"
                onclick="handleScanAsset('${escHtml(a.id)}', '${escHtml(a.domain)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M6 1.5A4.5 4.5 0 1 1 1.5 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <path d="M1.5 1.5V6h4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Scan Now
        </button>
        <button class="btn btn-danger btn-sm"
                onclick="handleDeleteAsset('${escHtml(a.id)}', '${escHtml(a.domain)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 3h8M5 1.5h2M4.5 9.5V5m3 4.5V5M3 3l.7 6.5h4.6L9 3"
                  stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Delete
        </button>
        <button class="btn btn-secondary btn-sm"
                onclick="handleDownloadReport('${escHtml(a.id)}', '${escHtml(a.domain)}', 'technical', this)"
                title="Скачать технический PDF-отчёт по безопасности">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <rect x="2" y="1" width="8" height="10" rx="1.2" stroke="currentColor" stroke-width="1.2"/>
            <path d="M4 4h4M4 6h3M4 8h2" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
          </svg>
          PDF Report
        </button>
        <button class="btn btn-secondary btn-sm"
                onclick="handleDownloadReport('${escHtml(a.id)}', '${escHtml(a.domain)}', 'executive', this)"
                title="Скачать executive PDF-отчёт для руководства">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 2h8v1.5l-4 3-4-3V2z" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/>
            <path d="M2 3.5v6.5h8V3.5" stroke="currentColor" stroke-width="1.1" stroke-linejoin="round"/>
            <path d="M4 7h4M4 8.5h2.5" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
          </svg>
          Exec Report
        </button>
      </div>
    </div>`;
}

async function handleScanAsset(id, domain, btn) {
  setLoading(btn, true);
  try {
    await API.scanAsset(id);
    Toast.show('success', 'Сканирование запущено', `Домен: ${domain}`);
    addScanLog('info', `Ручное сканирование: ${domain}`, 'processing');
  } catch (e) {
    Toast.show('error', 'Ошибка запуска скана', e.message);
  } finally {
    setLoading(btn, false);
  }
}

async function handleDeleteAsset(id, domain, btn) {
  if (!confirm(`Удалить актив "${domain}"? Это действие нельзя отменить.`)) return;
  setLoading(btn, true);
  try {
    await API.deleteAsset(id);
    Toast.show('success', 'Актив удалён', domain);
    renderAssets();
  } catch (e) {
    Toast.show('error', 'Ошибка удаления', e.message);
    setLoading(btn, false);
  }
}

/**
 * Скачивает PDF-отчёт для актива.
 * @param {string} id       — asset_id
 * @param {string} domain   — домен для имени файла
 * @param {'technical'|'executive'} type
 * @param {HTMLButtonElement} btn
 */
async function handleDownloadReport(id, domain, type, btn) {
  setLoading(btn, true);
  try {
    await API.downloadReport(id, type, domain);
    const label = type === 'executive' ? 'Executive Report' : 'Security Report';
    Toast.show('success', `${label} скачан`, domain);
  } catch (e) {
    Toast.show('error', 'Ошибка генерации отчёта', e.message);
  } finally {
    setLoading(btn, false);
  }
}

function openAddAssetModal() {
  const form = document.getElementById('add-asset-form');
  if (form) form.reset();
  Modal.open('add-asset-modal');
}

async function submitAddAsset() {
  const domain = document.getElementById('asset-domain-input').value.trim();
  const desc   = document.getElementById('asset-desc-input').value.trim();
  if (!domain) {
    Toast.show('warning', 'Укажите домен');
    return;
  }
  const btn = document.getElementById('add-asset-submit');
  setLoading(btn, true);
  try {
    await API.createAsset({ domain, description: desc || undefined });
    Toast.show('success', 'Актив добавлен', domain);
    Modal.close('add-asset-modal');
    renderAssets();
  } catch (e) {
    Toast.show('error', 'Ошибка создания', e.message);
  } finally {
    setLoading(btn, false);
  }
}

// ─────────────────────────────────────────────
// TAB: Events — с polling и critical-toast
// ─────────────────────────────────────────────

async function renderEvents() {
  await loadEventsPage();
  startEventsPolling();
}

async function loadEventsPage() {
  const limit  = PAGE_SIZE;
  const offset = (State.eventsPage - 1) * PAGE_SIZE;
  const f      = State.eventsFilters;
  const fetchLimit = Math.min(offset + limit + 1, 500);

  const tbody = document.getElementById('events-tbody');
  if (tbody) {
    tbody.innerHTML = `<tr><td colspan="6"
      style="text-align:center;padding:2rem;color:var(--text-muted)">
      <span class="spinner" style="display:inline-block;margin-right:.5rem"></span>Загрузка…
    </td></tr>`;
  }

  try {
    const all = await API.getEvents({
      severity:   f.severity   || undefined,
      event_type: f.event_type || undefined,
      domain:     f.domain     || undefined,
      limit:      fetchLimit,
    });

    // Ищем новые critical события и показываем toast
    _checkNewCritical(all);

    State.eventsData  = all;
    State.eventsTotal = all.length;
    State.eventsLastUpdated = new Date();

    const page = all.slice(offset, offset + limit);
    buildEventsTable(page);
    buildPagination(all.length);
    _updateEventsLastUpdated();
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки событий', e.message);
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6">${emptyStateHtml('Не удалось загрузить события')}</td></tr>`;
    }
  }
}

/** Проверяем появились ли новые critical события */
function _checkNewCritical(events) {
  if (!State.eventsCriticalIds.size) {
    // Первая загрузка — запомним все critical IDs без toast
    events.forEach(ev => {
      if ((ev.severity || '').toLowerCase() === 'critical') {
        State.eventsCriticalIds.add(ev.id);
      }
    });
    return;
  }

  events.forEach(ev => {
    if ((ev.severity || '').toLowerCase() === 'critical'
        && !State.eventsCriticalIds.has(ev.id)) {
      State.eventsCriticalIds.add(ev.id);
      Toast.show('error', 'Новое CRITICAL событие!',
        `${ev.event_type} — ${ev.target_domain}`);
    }
  });
}

/** Обновляет строку «Последнее обновление» под таблицей */
function _updateEventsLastUpdated() {
  const el = document.getElementById('events-last-updated');
  if (el && State.eventsLastUpdated) {
    el.textContent = `Последнее обновление: ${fmtTime(State.eventsLastUpdated)}`;
  }
}

/** Real-time polling событий каждые 30 секунд */
function startEventsPolling() {
  stopEventsPolling();
  State.eventsPollingTimer = setInterval(() => {
    // Останавливаем когда вкладка скрыта
    if (document.hidden) return;
    // Обновляем только если мы на вкладке Events
    const eventsActive = document.getElementById('tab-events')?.classList.contains('active');
    if (eventsActive) loadEventsPage();
  }, REFRESH_INTERVAL * 1000);
}

function stopEventsPolling() {
  if (State.eventsPollingTimer) {
    clearInterval(State.eventsPollingTimer);
    State.eventsPollingTimer = null;
  }
}

function _payloadHtml(ev) {
  if (ev.event_type !== 'stealer_log') {
    return `<pre class="json-pre">${escHtml(prettyJson(ev.payload))}</pre>`;
  }
  // Stealer-log: показываем login/url открыто, пароль скрыт
  const p = ev.payload || {};
  const hasEnc = !!p.password_enc;
  return `
    <div style="display:grid;gap:.35rem;font-size:.8125rem;font-family:var(--font-mono)">
      <div><span style="color:var(--text-muted)">URL:   </span><span>${escHtml(p.url || '—')}</span></div>
      <div><span style="color:var(--text-muted)">Login: </span><span>${escHtml(p.login || '—')}</span></div>
      <div style="display:flex;align-items:center;gap:.6rem">
        <span style="color:var(--text-muted)">Pass:  </span>
        <span id="pwd-${escHtml(ev.id)}">***</span>
        ${hasEnc ? `<button class="btn btn-secondary btn-sm"
          style="font-size:.75rem;padding:.15rem .5rem"
          onclick="revealPassword('${escHtml(ev.id)}')">Показать</button>` : ''}
      </div>
      ${p.source_file ? `<div><span style="color:var(--text-muted)">File:  </span><span>${escHtml(p.source_file)}</span></div>` : ''}
      ${p.channel    ? `<div><span style="color:var(--text-muted)">Chan:  </span><span>${escHtml(p.channel)}</span></div>` : ''}
    </div>`;
}

function buildEventsTable(events) {
  const tbody = document.getElementById('events-tbody');
  if (!tbody) return;
  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="6">${emptyStateHtml('Событий не найдено')}</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map(ev => {
    const isCritical = (ev.severity || '').toLowerCase() === 'critical';
    return `
    <tr data-id="${escHtml(ev.id)}"
        class="${isCritical ? 'row-critical' : ''}"
        onclick="toggleEventRow(this)">
      <td>${severityBadge(ev.severity)}</td>
      <td><code style="font-size:.8125rem">${escHtml(ev.event_type)}</code></td>
      <td><span class="domain-tag">${escHtml(ev.target_domain)}</span></td>
      <td style="color:var(--text-2)">${escHtml(ev.source_type)}</td>
      <td style="color:var(--text-2)">${escHtml(truncate(ev.source_name, 32))}</td>
      <td style="color:var(--text-muted);font-size:.8125rem;white-space:nowrap">${fmtDate(ev.detected_at)}</td>
    </tr>
    <tr class="row-detail" id="detail-${escHtml(ev.id)}">
      <td colspan="6" style="padding:.75rem 1rem 1rem 2.5rem">
        <strong style="color:var(--text-2);font-size:.8125rem;display:block;margin-bottom:.4rem">Payload:</strong>
        ${_payloadHtml(ev)}
      </td>
    </tr>`;
  }).join('');
}

async function revealPassword(eventId) {
  const el  = document.getElementById(`pwd-${eventId}`);
  const btn = el && el.nextElementSibling;
  if (!el) return;

  if (el.dataset.revealed === '1') {
    el.textContent = '***';
    el.dataset.revealed = '0';
    if (btn) btn.textContent = 'Показать';
    return;
  }

  if (btn) btn.disabled = true;
  try {
    const res  = await API.request(`/api/v1/events/${eventId}/reveal`, { method: 'POST' });
    if (!res) return;
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    el.textContent      = data.password || '(пусто)';
    el.dataset.revealed = '1';
    el.style.color      = 'var(--sev-critical)';
    if (btn) { btn.textContent = 'Скрыть'; btn.disabled = false; }
  } catch (err) {
    Toast.show('error', 'Ошибка расшифровки', err.message);
    if (btn) btn.disabled = false;
  }
}

function buildPagination(total) {
  const pages   = Math.ceil(total / PAGE_SIZE) || 1;
  const current = State.eventsPage;
  const start   = (current - 1) * PAGE_SIZE + 1;
  const end     = Math.min(current * PAGE_SIZE, total);

  const info = document.getElementById('pagination-info');
  if (info) info.textContent = total ? `${start}–${end} из ${total}` : 'Нет данных';

  const ctrl  = document.getElementById('pagination-controls');
  const range = buildPageRange(current, pages);
  if (!ctrl) return;

  ctrl.innerHTML = `
    <button class="page-btn" onclick="goToPage(${current - 1})"
            ${current <= 1 ? 'disabled' : ''}>‹</button>
    ${range.map(p => p === '…'
      ? `<span class="page-btn" style="cursor:default">…</span>`
      : `<button class="page-btn ${p === current ? 'active' : ''}"
               onclick="goToPage(${p})">${p}</button>`
    ).join('')}
    <button class="page-btn" onclick="goToPage(${current + 1})"
            ${current >= pages ? 'disabled' : ''}>›</button>`;
}

/** Умный диапазон страниц с многоточием */
function buildPageRange(current, pages) {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  const result = [1];
  if (current > 3) result.push('…');
  for (let p = Math.max(2, current - 1); p <= Math.min(pages - 1, current + 1); p++) result.push(p);
  if (current < pages - 2) result.push('…');
  result.push(pages);
  return result;
}

function goToPage(page) {
  const maxPage = Math.ceil(State.eventsTotal / PAGE_SIZE) || 1;
  if (page < 1 || page > maxPage) return;
  State.eventsPage = page;
  buildEventsTable(State.eventsData.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE));
  buildPagination(State.eventsTotal);
}

function applyEventsFilter() {
  State.eventsPage    = 1;
  State.eventsFilters = {
    severity:   document.getElementById('filter-severity')?.value || '',
    event_type: document.getElementById('filter-type')?.value || '',
    domain:     document.getElementById('filter-domain')?.value.trim() || '',
  };
  loadEventsPage();
}

function clearEventsFilter() {
  const sev = document.getElementById('filter-severity');
  const typ = document.getElementById('filter-type');
  const dom = document.getElementById('filter-domain');
  if (sev) sev.value = '';
  if (typ) typ.value = '';
  if (dom) dom.value = '';
  State.eventsFilters = { severity: '', event_type: '', domain: '' };
  State.eventsPage    = 1;
  loadEventsPage();
}

// ─────────────────────────────────────────────
// TAB: Alerts
// ─────────────────────────────────────────────

async function renderAlerts() {
  const container = document.getElementById('alerts-list');
  if (container) {
    container.innerHTML = `<div class="loading-skeleton skeleton-line" style="height:60px"></div>`;
  }
  try {
    const alerts = await API.getAlerts();
    State.alertsData = alerts;
    buildAlertsList(alerts);
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки алертов', e.message);
    if (container) container.innerHTML = emptyStateHtml('Не удалось загрузить правила');
  }
}

function buildAlertsList(rules) {
  const container = document.getElementById('alerts-list');
  if (!container) return;
  if (!rules.length) {
    container.innerHTML = emptyStateHtml('Правил алертов нет. Создайте первое.');
    return;
  }
  container.innerHTML = rules.map(r => `
    <div class="alert-rule-card" id="rule-${escHtml(r.id)}">
      <div class="alert-rule-info">
        <div class="alert-rule-name">
          ${escHtml(r.name)}
          ${r.is_active
            ? '<span class="badge badge-success" style="margin-left:.5rem">Active</span>'
            : '<span class="badge badge-danger" style="margin-left:.5rem">Inactive</span>'}
        </div>
        <div class="alert-rule-meta">
          <span>Min severity: ${severityBadge(r.min_severity)}</span>
          ${r.target_domain
            ? `<span class="domain-tag">${escHtml(r.target_domain)}</span>`
            : '<span style="color:var(--text-muted)">Все домены</span>'}
          <span>Chat: <code>${escHtml(r.telegram_chat_id)}</code></span>
          ${r.event_types
            ? `<span>Types: ${r.event_types.map(t => `<code>${escHtml(t)}</code>`).join(', ')}</span>`
            : ''}
        </div>
      </div>
      <div class="alert-rule-actions">
        <button class="btn btn-secondary btn-sm"
                onclick="handleTestAlert('${escHtml(r.id)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 6l3 3 5-5" stroke="currentColor" stroke-width="1.5"
                  stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Test
        </button>
        <button class="btn btn-danger btn-sm"
                onclick="handleDeleteAlert('${escHtml(r.id)}', '${escHtml(r.name)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 3h8M5 1.5h2M4.5 9.5V5m3 4.5V5M3 3l.7 6.5h4.6L9 3"
                  stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Delete
        </button>
      </div>
    </div>`).join('');
}

async function handleTestAlert(id, btn) {
  setLoading(btn, true);
  try {
    await API.testAlert(id);
    Toast.show('success', 'Тест отправлен', 'Telegram-сообщение отправлено');
  } catch (e) {
    Toast.show('error', 'Ошибка теста алерта', e.message);
  } finally {
    setLoading(btn, false);
  }
}

async function handleDeleteAlert(id, name, btn) {
  if (!confirm(`Удалить правило "${name}"?`)) return;
  setLoading(btn, true);
  try {
    await API.deleteAlert(id);
    Toast.show('success', 'Правило удалено', name);
    renderAlerts();
  } catch (e) {
    Toast.show('error', 'Ошибка удаления', e.message);
    setLoading(btn, false);
  }
}

async function submitCreateAlert() {
  const name   = document.getElementById('alert-name')?.value.trim() || '';
  const domain = document.getElementById('alert-domain')?.value.trim() || '';
  const minSev = document.getElementById('alert-min-severity')?.value || 'medium';
  const chatId = document.getElementById('alert-chat-id')?.value.trim() || '';

  if (!name || !chatId) {
    Toast.show('warning', 'Заполните обязательные поля', 'Имя и Telegram chat_id обязательны');
    return;
  }

  const body = {
    name,
    min_severity: minSev,
    telegram_chat_id: chatId,
    ...(domain ? { target_domain: domain } : {}),
  };

  const btn = document.getElementById('create-alert-btn');
  setLoading(btn, true);
  try {
    await API.createAlert(body);
    Toast.show('success', 'Правило создано', name);
    document.getElementById('create-alert-form')?.reset();
    renderAlerts();
  } catch (e) {
    Toast.show('error', 'Ошибка создания правила', e.message);
  } finally {
    setLoading(btn, false);
  }
}

// ─────────────────────────────────────────────
// TAB: Scan
// ─────────────────────────────────────────────

const SCAN_LOG_KEY = 'easm_scan_log';
const MAX_SCAN_LOG = 30;

function addScanLog(status, domain, detail) {
  const logs = getScanLogs();
  logs.unshift({ ts: new Date().toISOString(), status, domain, detail });
  if (logs.length > MAX_SCAN_LOG) logs.length = MAX_SCAN_LOG;
  localStorage.setItem(SCAN_LOG_KEY, JSON.stringify(logs));
  renderScanLog();
}

function getScanLogs() {
  try {
    return JSON.parse(localStorage.getItem(SCAN_LOG_KEY) || '[]');
  } catch {
    return [];
  }
}

function renderScanLog() {
  const container = document.getElementById('scan-log');
  if (!container) return;
  const logs = getScanLogs();
  if (!logs.length) {
    container.innerHTML = '<span style="color:var(--text-muted)">Запусков пока не было</span>';
    return;
  }
  container.innerHTML = logs.map(l => {
    const cls = l.status === 'ok'    ? 'scan-log-status-ok'
      : l.status === 'error' ? 'scan-log-status-error'
      : 'scan-log-status-info';
    return `
      <div class="scan-log-entry">
        <span class="scan-log-time">${fmtDate(l.ts)}</span>
        <span class="${cls}">${escHtml(l.status.toUpperCase())}</span>
        <span>${escHtml(l.domain)}</span>
        <span style="color:var(--text-muted)">${escHtml(l.detail)}</span>
      </div>`;
  }).join('');
}

function renderScan() {
  renderScanLog();
}

async function handleStartScan() {
  const domainInput = document.getElementById('scan-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен');
    return;
  }

  const selected = [...document.querySelectorAll('.module-chip.selected')]
    .map(el => el.dataset.module);

  if (!selected.length) {
    Toast.show('warning', 'Выберите хотя бы один модуль');
    return;
  }

  const btn = document.getElementById('start-scan-btn');
  setLoading(btn, true);

  const results = [];
  for (const mod of selected) {
    try {
      await API.startScan(mod, domain);
      results.push(`${mod}: OK`);
      addScanLog('ok', domain, `${mod}: запущен`);
    } catch (e) {
      results.push(`${mod}: ${e.message}`);
      addScanLog('error', domain, `${mod}: ${e.message}`);
    }
  }

  Toast.show(
    results.every(r => r.endsWith('OK')) ? 'success' : 'warning',
    `Сканирование ${domain}`,
    results.join('; '),
  );
  setLoading(btn, false);
}

function toggleModule(chip) {
  chip.classList.toggle('selected');
}

// ─────────────────────────────────────────────
// TAB: Darknet Monitoring
// ─────────────────────────────────────────────

function renderDarknet() {
  // Инициализация вкладки, если нужно (данные уже в HTML)
  const tbody = document.getElementById('darknet-events-tbody');
  if (tbody && tbody.children.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('Событий пока нет')}</td></tr>`;
  }
}

async function handleHardeningScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для проверки периметра');
    if (domainInput) domainInput.focus();
    return;
  }
  const btn = document.getElementById('hardening-scan-btn');
  setLoading(btn, true);
  try {
    await API.scanHardening(domain);
    Toast.show('success', 'Проверка периметра запущена', `SPF / DMARC / AXFR / SSL для ${domain}`);
    addScanLog('ok', domain, 'hardening: запущен');
  } catch (e) {
    Toast.show('error', 'Ошибка проверки периметра', e.message);
    addScanLog('error', domain, `hardening: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

async function handlePhishingScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для проверки фишинга');
    if (domainInput) domainInput.focus();
    return;
  }
  const btn = document.getElementById('phishing-scan-btn');
  setLoading(btn, true);
  try {
    await API.scanPhishing(domain);
    Toast.show('success', 'Проверка фишинга запущена', `Тайпосквот-анализ для ${domain}`);
    addScanLog('ok', domain, 'phishing: запущен');
  } catch (e) {
    Toast.show('error', 'Ошибка проверки фишинга', e.message);
    addScanLog('error', domain, `phishing: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

async function handlePortScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для сканирования портов');
    if (domainInput) domainInput.focus();
    return;
  }
  const btn = document.getElementById('port-scan-btn');
  setLoading(btn, true);
  try {
    await API.scanPorts(domain);
    Toast.show('success', 'Сканирование портов запущено', `nmap по публичным IP для ${domain}`);
    addScanLog('ok', domain, 'port scan: запущен');
  } catch (e) {
    Toast.show('error', 'Ошибка сканирования портов', e.message);
    addScanLog('error', domain, `port scan: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

async function handleS3Scan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для поиска S3 бакетов');
    if (domainInput) domainInput.focus();
    return;
  }
  const btn = document.getElementById('s3-scan-btn');
  setLoading(btn, true);
  try {
    await API.scanS3(domain);
    Toast.show('success', 'Поиск S3 бакетов запущен', `Проверка бакетов по имени компании для ${domain}`);
    addScanLog('ok', domain, 's3 scan: запущен');
  } catch (e) {
    Toast.show('error', 'Ошибка поиска S3 бакетов', e.message);
    addScanLog('error', domain, `s3 scan: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

/**
 * Проверка поддоменов на Subdomain Takeover (задача 9.B).
 * Резолвит CNAME → проверяет fingerprint уязвимого сервиса.
 */
async function handleTakeoverScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для проверки Subdomain Takeover');
    if (domainInput) domainInput.focus();
    return;
  }
  const btn = document.getElementById('takeover-scan-btn');
  setLoading(btn, true);
  try {
    const data = await API.scanTakeover(domain);
    const checked = data.subdomains_checked || 0;
    if (data.status === 'skipped') {
      Toast.show('warning', 'Нет поддоменов для проверки', data.detail || 'Сначала запустите сканирование поддоменов');
      addScanLog('warn', domain, `takeover: нет поддоменов`);
    } else {
      Toast.show('success', 'Takeover проверка запущена', `Проверяется ${checked} поддоменов для ${domain}`);
      addScanLog('ok', domain, `takeover: запущен (${checked} поддоменов)`);
    }
  } catch (e) {
    Toast.show('error', 'Ошибка Subdomain Takeover', e.message);
    addScanLog('error', domain, `takeover: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

/**
 * TLS / JA4 fingerprinting (задача 9.A).
 * Анализирует TLS-конфигурацию: версия, шифр, WAF, срок сертификата, JA4S.
 */
async function handleTlsScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для TLS/JA4 сканирования');
    if (domainInput) domainInput.focus();
    return;
  }
  const btn = document.getElementById('tls-scan-btn');
  setLoading(btn, true);
  try {
    await API.scanTls(domain);
    Toast.show('success', 'TLS/JA4 сканирование запущено', `Анализ TLS-конфигурации для ${domain}`);
    addScanLog('ok', domain, 'tls/ja4: запущен');
  } catch (e) {
    Toast.show('error', 'Ошибка TLS/JA4 сканирования', e.message);
    addScanLog('error', domain, `tls/ja4: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

/**
 * Shodan Enrichment — обогащение данных о домене (задача 9.J).
 * Запрашивает Shodan API для публичных IP домена, ищет Asset Drift.
 * Graceful: если SHODAN_API_KEY не задан — показывает info, не ошибку.
 */
async function handleEnrichScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для Shodan Enrichment');
    if (domainInput) domainInput.focus();
    return;
  }

  const btn = document.getElementById('enrich-scan-btn');
  setLoading(btn, true);
  try {
    const res = await API.request('/api/v1/scan/enrich', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    });
    if (!res || !res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res?.status}`);
    }
    const data = await res.json();

    if (data.status === 'skipped') {
      Toast.show('info', 'Shodan ключ не настроен', 'Добавьте SHODAN_API_KEY в .env для обогащения данных');
      addScanLog('info', domain, 'shodan enrich: skipped (нет ключа)');
    } else if (data.status === 'processing') {
      Toast.show('success', 'Shodan Enrichment запущен', `Результаты появятся в Events (asset_drift)`);
      addScanLog('ok', domain, 'shodan enrich: запущен в фоне');
    } else {
      Toast.show(
        'success',
        'Shodan Enrichment завершён',
        `Проверено IP: ${data.ips_checked || 0}, скрытых портов: ${data.hidden_ports_found || 0}`,
      );
      addScanLog('ok', domain, `shodan enrich: IP=${data.ips_checked || 0}, скрытых портов=${data.hidden_ports_found || 0}`);
    }
  } catch (e) {
    Toast.show('error', 'Ошибка Shodan Enrichment', e.message);
    addScanLog('error', domain, `shodan enrich: ${e.message}`);
  } finally {
    setLoading(btn, false);
  }
}

/**
 * Проверка живых сессий из стилер-лога (задача 9.C).
 * Пассивный HEAD-запрос — не генерирует алертов на WAF/EDR жертвы.
 */
async function handleCookieValidation() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен в поле выше');
    if (domainInput) domainInput.focus();
    return;
  }

  const btn    = document.getElementById('cookie-validate-btn');
  const status = document.getElementById('cookie-scan-status');

  setLoading(btn, true);
  if (status) {
    status.style.display = 'block';
    status.innerHTML = `
      <div style="color:var(--accent);display:flex;align-items:center;gap:.5rem;font-size:.875rem">
        <span class="spinner"></span>
        Проверка живых сессий для <strong>${escHtml(domain)}</strong>… (до 30 секунд)
      </div>`;
  }

  try {
    const data = await API.scanCookies(domain);
    addScanLog('ok', domain, 'cookie scan: запущен');

    if (status) {
      status.innerHTML = `
        <div style="background:var(--success-bg);border:1px solid rgba(63,185,80,.3);
                    border-radius:8px;padding:.875rem 1rem;color:var(--success);font-size:.875rem">
          Проверка запущена для <strong>${escHtml(domain)}</strong>.
          Результаты появятся в Events (event_type: active_session_leak).
        </div>`;
    }
    Toast.show('success', 'Cookie-проверка запущена', `Домен: ${domain}`);

  } catch (e) {
    const isNotFound = e.message.includes('не найдены') || e.message.includes('not found');
    if (isNotFound) {
      Toast.show('warning', 'Стилер-архивы не найдены', 'Сначала загрузите ZIP-файл стилер-лога');
    } else {
      Toast.show('error', 'Ошибка проверки сессий', e.message);
    }
    addScanLog('error', domain, `cookie scan: ${e.message}`);
    if (status) {
      status.innerHTML = `
        <div style="background:var(--danger-bg);border:1px solid rgba(248,81,73,.3);
                    border-radius:8px;padding:.875rem 1rem;color:var(--danger);font-size:.875rem">
          ${escHtml(e.message)}
        </div>`;
    }
  } finally {
    setLoading(btn, false);
  }
}

async function handleDarknetScan() {
  const domainInput = document.getElementById('darknet-domain');
  const domain = domainInput?.value.trim() || '';
  if (!domain) {
    Toast.show('warning', 'Укажите домен для мониторинга');
    if (domainInput) domainInput.focus();
    return;
  }

  const btn    = document.getElementById('darknet-scan-btn');
  const status = document.getElementById('darknet-scan-status');

  setLoading(btn, true);
  if (status) {
    status.style.display = 'block';
    status.innerHTML = `
      <div style="color:var(--accent);display:flex;align-items:center;gap:.5rem;font-size:.875rem">
        <span class="spinner"></span>
        Запуск мониторинга для <strong>${escHtml(domain)}</strong>…
      </div>`;
  }

  try {
    const data = await API.scanDarknet(domain);
    Toast.show('success', 'Мониторинг запущен', `Домен: ${domain}`);
    addScanLog('ok', domain, 'darknet scan: запущен');

    if (status) {
      status.innerHTML = `
        <div style="background:var(--success-bg);border:1px solid rgba(63,185,80,.3);
                    border-radius:8px;padding:.875rem 1rem;color:var(--success);font-size:.875rem">
          Мониторинг Darknet запущен для <strong>${escHtml(domain)}</strong>.
          Результаты появятся в таблице ниже.
        </div>`;
    }

    // Перезагружаем таблицу darknet-событий
    await loadDarknetEvents(domain);

  } catch (e) {
    Toast.show('error', 'Ошибка запуска darknet-сканирования', e.message);
    if (status) {
      status.innerHTML = `
        <div style="background:var(--danger-bg);border:1px solid rgba(248,81,73,.3);
                    border-radius:8px;padding:.875rem 1rem;color:var(--danger);font-size:.875rem">
          Ошибка: ${escHtml(e.message)}
        </div>`;
    }
  } finally {
    setLoading(btn, false);
  }
}

/** Загружает darknet-события из общего API с фильтром по типу */
async function loadDarknetEvents(domain) {
  const tbody = document.getElementById('darknet-events-tbody');
  if (!tbody) return;

  tbody.innerHTML = `<tr><td colspan="5"
    style="text-align:center;padding:2rem;color:var(--text-muted)">
    <span class="spinner" style="display:inline-block;margin-right:.5rem"></span>Загрузка…
  </td></tr>`;

  try {
    const events = await API.getEvents({
      event_type: 'darknet_mention',
      domain: domain || undefined,
      limit: 100,
    });

    if (!events.length) {
      tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('Darknet-событий не найдено')}</td></tr>`;
      return;
    }

    tbody.innerHTML = events.map(ev => `
      <tr data-id="${escHtml(ev.id)}" onclick="toggleEventRow(this)">
        <td>${severityBadge(ev.severity)}</td>
        <td><span class="domain-tag">${escHtml(ev.target_domain)}</span></td>
        <td style="color:var(--text-2)">${escHtml(ev.source_name || '—')}</td>
        <td style="color:var(--text-muted);font-size:.8125rem">${fmtDate(ev.detected_at)}</td>
        <td>
          <code style="font-size:.75rem;color:var(--text-2)">${escHtml(truncate(ev.payload?.excerpt || '—', 50))}</code>
        </td>
      </tr>
      <tr class="row-detail" id="detail-${escHtml(ev.id)}">
        <td colspan="5">
          <pre class="json-pre">${escHtml(prettyJson(ev.payload))}</pre>
        </td>
      </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('Ошибка загрузки')}</td></tr>`;
  }
}

// ─────────────────────────────────────────────
// Навигация по табам
// ─────────────────────────────────────────────

const TAB_LOADERS = {
  dashboard: () => { renderDashboard(); startDashboardRefresh(); },
  assets:    () => { stopDashboardRefresh(); stopEventsPolling(); renderAssets(); },
  events:    () => { stopDashboardRefresh(); renderEvents(); },
  alerts:    () => { stopDashboardRefresh(); stopEventsPolling(); renderAlerts(); },
  scan:      () => { stopDashboardRefresh(); stopEventsPolling(); renderScan(); },
  darknet:   () => { stopDashboardRefresh(); stopEventsPolling(); renderDarknet(); },
  // MSSP (задача 9.F): перезагружаем при каждом переключении на вкладку
  mssp:      () => { stopDashboardRefresh(); stopEventsPolling(); loadMsspClients(); },
  // Attack Graph (задача 9.E): показываем вкладку, данные загружаются по кнопке
  graph:     () => { stopDashboardRefresh(); stopEventsPolling(); },
};

function switchTab(name) {
  document.querySelectorAll('.nav-tab').forEach(t =>
    t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p =>
    p.classList.toggle('active', p.id === `tab-${name}`));

  const loader = TAB_LOADERS[name];
  if (loader) loader();
}

// ─────────────────────────────────────────────
// Авторизация
// ─────────────────────────────────────────────

function checkAuth() {
  if (!API.getToken()) {
    window.location.href = '/login.html';
    return false;
  }
  return true;
}

function handleLogout() {
  API.clearToken();
  window.location.href = '/login.html';
}

// ─────────────────────────────────────────────
// Охота на стилер-логи
// ─────────────────────────────────────────────

let _stealerFile = null;

function handleStealerFileSelect(input) {
  _stealerFile = input.files[0] || null;
  _updateStealerUI();
}

function handleStealerDrop(event) {
  event.preventDefault();
  document.getElementById('stealer-drop-zone')?.classList.remove('drag-over');
  const file = event.dataTransfer.files[0];
  if (!file) return;
  if (!/\.(zip|txt|log|csv)$/i.test(file.name)) {
    Toast.show('warning', 'Неверный формат', 'Поддерживаются: .zip .txt .log .csv');
    return;
  }
  _stealerFile = file;
  _updateStealerUI();
}

function _updateStealerUI() {
  const infoEl  = document.getElementById('stealer-file-info');
  const labelEl = document.getElementById('stealer-drop-label');
  const btn     = document.getElementById('stealer-upload-btn');

  if (_stealerFile) {
    const mb = (_stealerFile.size / 1048576).toFixed(2);
    if (infoEl)  infoEl.textContent = `${_stealerFile.name} — ${mb} МБ`;
    if (labelEl) labelEl.innerHTML  = 'Файл выбран. <span style="color:var(--accent);cursor:pointer">Заменить</span>';
    if (btn)     btn.disabled = false;
  } else {
    if (infoEl)  infoEl.textContent = '';
    if (labelEl) labelEl.innerHTML  = 'Перетащите ZIP / TXT или <span style="color:var(--accent);cursor:pointer">выберите файл</span>';
    if (btn)     btn.disabled = true;
  }
}

async function handleStealerUpload() {
  if (!_stealerFile) {
    Toast.show('warning', 'Выберите файл');
    return;
  }

  const btn        = document.getElementById('stealer-upload-btn');
  const resultEl   = document.getElementById('stealer-result');
  const progressEl = document.getElementById('stealer-progress');
  const fillEl     = document.getElementById('stealer-progress-fill');
  const domainsRaw = document.getElementById('stealer-domains')?.value.trim() || '';

  setLoading(btn, true);
  if (resultEl) resultEl.style.display = 'none';

  // Показываем прогресс-бар
  if (progressEl) progressEl.classList.add('visible');
  if (fillEl)     fillEl.style.width = '0%';

  try {
    const token = API.getToken();
    const fd    = new FormData();
    fd.append('file', _stealerFile);

    let url = '/api/v1/stealer/upload';
    if (domainsRaw) url += `?domains=${encodeURIComponent(domainsRaw)}`;

    // XHR для прогресс-бара (fetch не поддерживает upload progress)
    const data = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', url);
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable && fillEl) {
          fillEl.style.width = `${Math.round(e.loaded / e.total * 100)}%`;
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status === 401) {
          API.clearToken();
          window.location.href = '/login.html';
          reject(new Error('Unauthorized'));
          return;
        }
        try {
          const json = JSON.parse(xhr.responseText);
          if (xhr.status >= 400) reject(new Error(json.detail || `HTTP ${xhr.status}`));
          else resolve(json);
        } catch {
          reject(new Error(`HTTP ${xhr.status}`));
        }
      });

      xhr.addEventListener('error', () => reject(new Error('Ошибка сети')));
      xhr.send(fd);
    });

    if (fillEl) fillEl.style.width = '100%';

    const domains = (data.target_domains || []).join(', ') || '—';
    if (resultEl) {
      resultEl.innerHTML = `
        <div style="background:var(--success-bg);border:1px solid rgba(63,185,80,.25);
                    border-radius:8px;padding:.875rem 1rem;margin-top:.5rem">
          <div style="color:var(--success);font-weight:600;margin-bottom:.5rem">
            Охота запущена — ${escHtml(_stealerFile.name)}
          </div>
          <div style="color:var(--text-2);font-size:.8125rem;line-height:1.6">
            Файл: <strong>${escHtml(_stealerFile.name)}</strong>
            (${(_stealerFile.size / 1048576).toFixed(2)} МБ)<br>
            Домены: <code>${escHtml(domains)}</code><br>
            Результаты появятся в
            <button class="btn btn-secondary btn-sm"
                    onclick="switchTab('events')"
                    style="padding:0 4px;text-decoration:underline;color:var(--accent);background:none;border:none">
              Events → stealer_log
            </button>
          </div>
        </div>`;
      resultEl.style.display = 'block';
    }

    addScanLog('ok', domains, `stealer upload: ${_stealerFile.name}`);
    Toast.show('success', 'Охота запущена', _stealerFile.name);

    // Сбрасываем форму и переключаем на Events
    _stealerFile = null;
    const fileInput = document.getElementById('stealer-file-input');
    if (fileInput) fileInput.value = '';
    _updateStealerUI();

    // Автоматически переключаемся на Events через 2 секунды
    setTimeout(() => switchTab('events'), 2000);

  } catch (err) {
    if (resultEl) {
      resultEl.innerHTML = `
        <div style="background:var(--danger-bg);border:1px solid rgba(248,81,73,.25);
                    border-radius:8px;padding:.875rem 1rem;color:var(--danger);font-size:.875rem">
          ${escHtml(err.message)}
        </div>`;
      resultEl.style.display = 'block';
    }
    Toast.show('error', 'Ошибка загрузки', err.message);
  } finally {
    setLoading(btn, false);
    setTimeout(() => {
      if (progressEl) progressEl.classList.remove('visible');
      if (fillEl)     fillEl.style.width = '0%';
    }, 800);
  }
}

// ─────────────────────────────────────────────
// Проверка по источникам стилер-логов
// ─────────────────────────────────────────────

async function handleStealerSources() {
  const domainInput  = document.getElementById('sources-domain');
  const extraTgInput = document.getElementById('sources-extra-tg');
  const btn          = document.getElementById('stealer-sources-btn');
  const resultEl     = document.getElementById('stealer-sources-result');
  const domain       = domainInput?.value.trim() || '';

  if (!domain) {
    Toast.show('warning', 'Укажите домен');
    domainInput?.focus();
    return;
  }

  const extraRaw = extraTgInput ? extraTgInput.value.trim() : '';
  const extra_tg_channels = extraRaw
    ? extraRaw.split(',').map(s => s.trim().replace(/^@/, '')).filter(Boolean)
    : [];

  setLoading(btn, true);
  if (resultEl) resultEl.style.display = 'none';

  try {
    const res = await API.request('/api/v1/scan/stealer-sources', {
      method: 'POST',
      body: JSON.stringify({ domain, extra_tg_channels }),
    });
    if (!res) return;
    const data = await res.json();

    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);

    const sources = data.sources || {};
    const rows = Object.entries(sources).map(([k, v]) => {
      const active = !String(v).includes('нет');
      return `<div style="display:flex;justify-content:space-between;padding:.3rem 0;
                          border-bottom:1px solid rgba(255,255,255,.04);font-size:.8125rem">
        <span style="color:var(--text-2)">${escHtml(k)}</span>
        <span style="color:${active ? 'var(--success)' : 'var(--sev-high)'}">${escHtml(String(v))}</span>
      </div>`;
    }).join('');

    if (resultEl) {
      resultEl.innerHTML = `
        <div style="background:rgba(99,102,241,.07);border:1px solid rgba(99,102,241,.25);
                    border-radius:8px;padding:.875rem 1rem;margin-top:.5rem">
          <div style="color:var(--accent);font-weight:600;margin-bottom:.5rem">
            Запрос отправлен — ${escHtml(domain)}
          </div>
          ${rows}
          <div style="color:var(--text-muted);font-size:.75rem;margin-top:.6rem">
            Результаты появятся в Events → stealer_log
          </div>
        </div>`;
      resultEl.style.display = 'block';
    }

    Toast.show('success', 'Источники опрошены', domain);

  } catch (err) {
    if (resultEl) {
      resultEl.innerHTML = `
        <div style="background:var(--danger-bg);border:1px solid rgba(248,81,73,.25);
                    border-radius:8px;padding:.875rem 1rem;color:var(--danger);font-size:.875rem">
          ${escHtml(err.message)}
        </div>`;
      resultEl.style.display = 'block';
    }
    Toast.show('error', 'Ошибка запроса', err.message);
  } finally {
    setLoading(btn, false);
  }
}

// ─────────────────────────────────────────────
// SaaS биллинг — виджет плана в хедере (задача 8.I)
// ─────────────────────────────────────────────

/**
 * Загружает данные тарифного плана с /api/v1/billing/plan
 * и обновляет виджет в хедере.
 * Тихо игнорирует ошибки — виджет просто не показывается.
 */
async function loadPlanInfo() {
  const badge   = document.getElementById('plan-badge');
  const nameEl  = document.getElementById('plan-name');
  const countEl = document.getElementById('domain-counter');

  if (!badge || !nameEl || !countEl) return;

  const data = await API.getBillingPlan();
  if (!data) return; // нет организации или пользователь без организации

  nameEl.textContent  = data.plan_label || data.plan.toUpperCase();
  countEl.textContent = `${data.domains_used}/${data.domain_limit} доменов`;

  // Подсветка при приближении к лимиту
  const pct = data.domain_limit > 0 ? data.domains_used / data.domain_limit : 0;
  badge.style.color = pct >= 1
    ? 'var(--sev-critical)'
    : pct >= 0.8
      ? 'var(--sev-high)'
      : '';

  badge.style.display = 'flex';
  badge.style.alignItems = 'center';
  badge.style.gap = '.35rem';
}

// ─────────────────────────────────────────────
// MSSP Multi-Tenancy панель (задача 9.F)
// ─────────────────────────────────────────────

/**
 * Загружает и отрисовывает список клиентов MSSP-оператора.
 *
 * Показывает вкладку MSSP в навигации если у текущего пользователя
 * есть доступ (is_mssp_operator или is_superuser).
 * При 403 — вкладка остаётся скрытой и функция тихо завершается.
 */
async function loadMsspClients() {
  const navTab = document.getElementById('mssp-nav-tab');
  const listEl = document.getElementById('mssp-clients-list');

  if (!listEl) return;

  // Skeleton-загрузка
  listEl.innerHTML = `
    <div class="loading-skeleton skeleton-line" style="height:60px;margin-bottom:.5rem"></div>
    <div class="loading-skeleton skeleton-line" style="height:60px;margin-bottom:.5rem;width:90%"></div>
    <div class="loading-skeleton skeleton-line" style="height:60px;width:75%"></div>`;

  try {
    const res = await API.request('/api/v1/mssp/clients');

    // 403 — пользователь не является MSSP-оператором, скрываем вкладку
    if (res && res.status === 403) {
      if (navTab) navTab.style.display = 'none';
      listEl.innerHTML = '';
      return;
    }

    if (!res || !res.ok) {
      listEl.innerHTML = emptyStateHtml('Не удалось загрузить клиентов MSSP');
      return;
    }

    // Доступ подтверждён — показываем вкладку
    if (navTab) navTab.style.display = '';

    const clients = await res.json();

    if (!clients.length) {
      listEl.innerHTML = `
        <div class="mssp-empty">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="1.2">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </svg>
          <p style="margin-top:.5rem">Клиентов пока нет.<br>
            Суперпользователь может привязать организации через<br>
            <code>POST /api/v1/mssp/clients/{'{org_id}'}/assign</code>
          </p>
        </div>`;
      return;
    }

    listEl.innerHTML = clients.map(c => _msspClientCardHtml(c)).join('');

  } catch (err) {
    listEl.innerHTML = emptyStateHtml('Ошибка загрузки MSSP-данных');
    Toast.show('error', 'MSSP: ошибка', err.message);
  }
}

/**
 * Генерирует HTML карточки клиента MSSP.
 * @param {Object} c — ClientRiskSummary от /api/v1/mssp/clients
 * @returns {string}
 */
function _msspClientCardHtml(c) {
  // Цвет Risk Score: зелёный 80+ / жёлтый 60+ / оранжевый 40+ / красный
  const scoreColor = c.risk_score >= 80
    ? '#22c55e'
    : c.risk_score >= 60
      ? '#eab308'
      : c.risk_score >= 40
        ? '#f97316'
        : '#ef4444';

  // Дельта: 0 = нейтральный, + = рост (зелёный ▲), - = падение (красный ▼)
  const deltaStr = c.risk_delta_24h > 0
    ? `<span style="color:#22c55e;font-weight:700">▲${c.risk_delta_24h}</span>`
    : c.risk_delta_24h < 0
      ? `<span style="color:#ef4444;font-weight:700">▼${Math.abs(c.risk_delta_24h)}</span>`
      : `<span style="color:var(--text-muted)">━ 0</span>`;

  // Визуальный акцент карточки по направлению delta
  const cardClass = c.risk_delta_24h < 0
    ? 'mssp-client-card mssp-degraded'
    : c.risk_delta_24h > 0
      ? 'mssp-client-card mssp-improved'
      : 'mssp-client-card';

  const criticalNote = c.critical_events > 0
    ? `<span style="color:#ef4444;font-weight:600">${c.critical_events} крит.</span>`
    : '0 крит.';

  const lastSeen = c.last_event_at
    ? `<br><span style="font-size:.75rem;color:var(--text-muted)">Последнее: ${fmtDate(c.last_event_at)}</span>`
    : '';

  const planKey = (c.plan || 'starter').toLowerCase();
  const planClass = `mssp-plan plan-${escHtml(planKey)}`;

  return `
    <div class="${cardClass}" data-org-id="${escHtml(c.organization_id)}">
      <div class="mssp-org-name" title="${escHtml(c.organization_name)}">
        ${escHtml(c.organization_name)}
      </div>
      <div class="mssp-score" style="color:${scoreColor}"
           title="Risk Score (0=плохо, 100=хорошо)">${c.risk_score}</div>
      <div class="mssp-delta" title="Изменение рейтинга за 24 часа">${deltaStr} за 24ч</div>
      <div class="mssp-meta">${c.domain_count} дом. &middot; ${criticalNote}${lastSeen}</div>
      <span class="${planClass}">${escHtml(c.plan.toUpperCase())}</span>
    </div>`;
}

// ─────────────────────────────────────────────
// Attack Graph — задача 9.E
// ─────────────────────────────────────────────

/**
 * Загружает пути атаки для указанного домена из /api/v1/graph/{domain}/attack-paths.
 * Домен берётся из поля #graph-domain-input.
 */
async function loadAttackPaths() {
  const inputEl = document.getElementById('graph-domain-input');
  const listEl  = document.getElementById('attack-paths-list');
  if (!listEl) return;

  const domain = inputEl ? inputEl.value.trim() : '';
  if (!domain) {
    listEl.innerHTML = `
      <div style="text-align:center;padding:2rem;color:var(--text-muted)">
        Введите домен в поле выше и нажмите «Найти пути»
      </div>`;
    return;
  }

  // Skeleton во время загрузки
  listEl.innerHTML = `
    <div class="loading-skeleton skeleton-line" style="height:76px;margin-bottom:.5rem"></div>
    <div class="loading-skeleton skeleton-line" style="height:76px;margin-bottom:.5rem;width:90%"></div>`;

  try {
    const res = await API.request(`/api/v1/graph/${encodeURIComponent(domain)}/attack-paths`);

    if (!res || !res.ok) {
      listEl.innerHTML = `
        <div style="text-align:center;padding:2rem;color:var(--text-muted)">
          Не удалось получить данные графа (статус: ${res ? res.status : 'нет ответа'})
        </div>`;
      return;
    }

    const paths = await res.json();

    if (!paths.length) {
      listEl.innerHTML = `
        <div style="text-align:center;padding:2.5rem 1rem;color:var(--text-muted)">
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none"
               stroke="currentColor" stroke-width="1.2"
               style="display:block;margin:0 auto .75rem;opacity:.4">
            <circle cx="12" cy="12" r="10"/>
            <path d="M9 12l2 2 4-4"/>
          </svg>
          Путей атаки не обнаружено для <strong>${escHtml(domain)}</strong>.<br>
          <span style="font-size:.8125rem;margin-top:.375rem;display:block">
            Запустите сканирование портов и проверку стилер-логов — данные попадут в граф автоматически.
          </span>
        </div>`;
      return;
    }

    listEl.innerHTML = paths.map(p => _attackPathCardHtml(p)).join('');

  } catch (err) {
    listEl.innerHTML = `
      <div style="text-align:center;padding:2rem;color:var(--sev-critical)">
        Ошибка: ${escHtml(err.message)}
      </div>`;
  }
}

/**
 * Рендерит HTML-карточку одного пути атаки.
 * @param {Object} p — элемент из /api/v1/graph/{domain}/attack-paths
 * @returns {string}
 */
function _attackPathCardHtml(p) {
  const isPortPath = p.attack_type === 'direct_access';
  const score      = p.risk_score != null ? p.risk_score : 100;
  const isMedium   = score < 95;

  const portInfo = isPortPath && p.port
    ? `${p.port}/${escHtml(p.service || '?')}`
    : '';
  const vulnInfo = !isPortPath && p.vuln
    ? `${escHtml(p.vuln)} (${escHtml((p.severity || '').toUpperCase())})`
    : '';
  const serviceLabel = portInfo || vulnInfo;
  const scoreColor   = score >= 95 ? 'var(--sev-critical)' : 'var(--sev-high)';

  return `
    <div class="attack-path-card${isMedium ? ' medium' : ''}">
      <div class="attack-path-icon">${isPortPath ? '🔓' : '🔥'}</div>
      <div class="attack-path-body">
        <div class="attack-path-asset">${escHtml(p.asset || 'unknown')}</div>
        ${serviceLabel
          ? `<div class="attack-path-service">${serviceLabel}</div>`
          : ''}
        <div class="attack-path-email">
          Утечка: <strong>${escHtml(p.leaked_email || '—')}</strong>
        </div>
        <div class="attack-path-risk">${escHtml(p.risk || '')}</div>
      </div>
      <div class="attack-path-score">
        <span class="attack-path-score-value" style="color:${scoreColor}">${score}</span>
        <span class="attack-path-score-label">риск</span>
      </div>
    </div>`;
}

// ─────────────────────────────────────────────
// Инициализация приложения
// ─────────────────────────────────────────────

function init() {
  // Применяем тему до рендера, чтобы не было мигания
  Theme.init();

  if (!checkAuth()) return;

  // Загружаем информацию о тарифном плане (задача 8.I)
  loadPlanInfo();

  // Проверяем доступ к MSSP-панели (задача 9.F).
  // Тихая проверка при старте: если 403 — вкладка остаётся скрытой.
  loadMsspClients();

  // Навигация
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Закрытие модалок
  Modal.bindBackdrop('add-asset-modal');

  // Enter в модальных формах
  document.querySelectorAll('.modal input').forEach(inp => {
    inp.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.target.closest('.modal')?.querySelector('.btn-primary')?.click();
      }
    });
  });

  // Debounce для текстового фильтра Events
  const filterDomain = document.getElementById('filter-domain');
  if (filterDomain) {
    let debounce;
    filterDomain.addEventListener('input', () => {
      clearTimeout(debounce);
      debounce = setTimeout(applyEventsFilter, 400);
    });
  }

  // Клики на chip-модулях
  document.querySelectorAll('.module-chip').forEach(chip => {
    chip.addEventListener('click', () => toggleModule(chip));
  });

  // Остановка polling при скрытии вкладки браузера
  document.addEventListener('visibilitychange', () => {
    // При возвращении — сразу обновить если мы на Events
    if (!document.hidden) {
      const eventsActive = document.getElementById('tab-events')?.classList.contains('active');
      if (eventsActive) loadEventsPage();
    }
  });

  // Показываем первый таб
  switchTab('dashboard');
}

// Старт после загрузки DOM
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
