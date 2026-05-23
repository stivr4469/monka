/**
 * EASM Security Dashboard — app.js
 * Vanilla JS, без фреймворков. Весь UI в этом файле.
 */

'use strict';

// ─────────────────────────────────────────────
// Константы
// ─────────────────────────────────────────────

const PAGE_SIZE = 20;         // строк на страницу в Events
const REFRESH_INTERVAL = 30;  // секунд для авто-обновления Dashboard

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
   * Базовый метод запроса.
   * При 401 — редирект на страницу логина.
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
    if (filters.limit)      params.set('limit', filters.limit);
    const qs = params.toString() ? `?${params}` : '';
    const res = await this.request(`/api/v1/events/${qs}`);
    if (!res || !res.ok) throw new Error(`Ошибка events: ${res?.status}`);
    return res.json();
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

  /**
   * DELETE /api/v1/assets/{id}
   */
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
   * module: 'subfinder' | 'github' | 'paste' | 'breach' | 'gitleaks'
   */
  static async startScan(module, domain) {
    const paths = {
      subfinder: '/api/v1/assets/',
      github:    '/api/v1/scan/github',
      paste:     '/api/v1/scan/paste',
    };
    if (module === 'subfinder') {
      // Subfinder запускается при создании актива
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
    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.innerHTML = `
      <span class="toast-icon" style="color:var(--sev-${type === 'error' ? 'critical' : type === 'warning' ? 'high' : type === 'success' ? '' : ''}${type === 'success' ? 'none' : ''}">${icons[type]}</span>
      <div class="toast-content">
        <div class="toast-title">${escHtml(title)}</div>
        ${msg ? `<div class="toast-msg">${escHtml(msg)}</div>` : ''}
      </div>`;

    // Цвет иконки через inline style для корректного соответствия типу
    const iconEl = el.querySelector('.toast-icon');
    const colorMap = { success: 'var(--success)', error: 'var(--sev-critical)', info: 'var(--accent)', warning: 'var(--sev-high)' };
    iconEl.style.color = colorMap[type];

    this.container.appendChild(el);
    setTimeout(() => {
      el.classList.add('hiding');
      setTimeout(() => el.remove(), 200);
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
    btn.innerHTML = `<span class="spinner"></span>${btn.textContent.trim() ? ' Загрузка…' : ''}`;
  } else {
    btn.disabled = false;
    btn.innerHTML = btn._origHtml || btn.innerHTML;
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

  // Assets
  assetsData: [],

  // Alerts
  alertsData: [],

  // Dashboard refresh timer
  refreshTimer: null,
  refreshCountdown: REFRESH_INTERVAL,
};

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
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки', e.message);
  }
}

function renderStats(stats) {
  const total    = stats.total || 0;
  const bySev    = stats.by_severity || {};
  const byType   = stats.by_type || {};

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
}

function renderRecentEvents(events) {
  const tbody = document.getElementById('recent-events-tbody');
  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="5">${emptyStateHtml('Событий пока нет')}</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map(ev => `
    <tr data-id="${escHtml(ev.id)}" onclick="toggleEventRow(this)">
      <td>${severityBadge(ev.severity)}</td>
      <td><code style="font-size:.8125rem">${escHtml(ev.event_type)}</code></td>
      <td><span class="domain-tag">${escHtml(ev.target_domain)}</span></td>
      <td>${escHtml(truncate(ev.source_name, 28))}</td>
      <td style="color:var(--text-muted);font-size:.8125rem">${fmtDate(ev.detected_at)}</td>
    </tr>
    <tr class="row-detail" id="detail-${escHtml(ev.id)}">
      <td colspan="5">
        <strong style="color:var(--text-secondary);font-size:.8125rem">Payload:</strong>
        <pre class="json-pre">${escHtml(prettyJson(ev.payload))}</pre>
      </td>
    </tr>`).join('');
}

/** Раскрыть/закрыть строку таблицы с payload */
function toggleEventRow(tr) {
  const id = tr.dataset.id;
  const detailRow = document.getElementById(`detail-${id}`);
  if (!detailRow) return;
  detailRow.classList.toggle('open');
}

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

// Авто-обновление Dashboard
function startDashboardRefresh() {
  stopDashboardRefresh();
  State.refreshCountdown = REFRESH_INTERVAL;
  updateRefreshCounter();

  State.refreshTimer = setInterval(() => {
    State.refreshCountdown--;
    updateRefreshCounter();
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

function updateRefreshCounter() {
  const el = document.getElementById('refresh-count');
  if (el) el.textContent = State.refreshCountdown;
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
        ID: <code style="font-size:.7rem">${escHtml(a.id.slice(0,8))}…</code>
      </div>
      <div class="asset-actions">
        <button class="btn btn-primary btn-sm" onclick="handleScanAsset('${escHtml(a.id)}', '${escHtml(a.domain)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M6 1.5A4.5 4.5 0 1 1 1.5 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
            <path d="M1.5 1.5V6h4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Scan Now
        </button>
        <button class="btn btn-danger btn-sm" onclick="handleDeleteAsset('${escHtml(a.id)}', '${escHtml(a.domain)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 3h8M5 1.5h2M4.5 9.5V5m3 4.5V5M3 3l.7 6.5h4.6L9 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Delete
        </button>
      </div>
    </div>`;
}

async function handleScanAsset(id, domain, btn) {
  setLoading(btn, true);
  try {
    await API.scanAsset(id);
    Toast.show('success', 'Сканирование запущено', `Домен: ${domain}`);
    // Записываем в лог сканов
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

// Форма добавления актива
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
// TAB: Events
// ─────────────────────────────────────────────

async function renderEvents() {
  await loadEventsPage();
}

async function loadEventsPage() {
  const limit  = PAGE_SIZE;
  const offset = (State.eventsPage - 1) * PAGE_SIZE;

  const f = State.eventsFilters;
  // API принимает limit, но не offset — загружаем с запасом и режем на клиенте
  const fetchLimit = offset + limit + 1;

  const tbody = document.getElementById('events-tbody');
  tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:2rem;color:var(--text-muted)">
    <span class="spinner" style="display:inline-block;margin-right:.5rem"></span>Загрузка…</td></tr>`;

  try {
    const all = await API.getEvents({
      severity: f.severity || undefined,
      event_type: f.event_type || undefined,
      domain: f.domain || undefined,
      limit: Math.min(fetchLimit, 500),
    });

    State.eventsData  = all;
    State.eventsTotal = all.length;

    const page = all.slice(offset, offset + limit);
    buildEventsTable(page);
    buildPagination(all.length);
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки событий', e.message);
    tbody.innerHTML = `<tr><td colspan="6">${emptyStateHtml('Не удалось загрузить события')}</td></tr>`;
  }
}

function buildEventsTable(events) {
  const tbody = document.getElementById('events-tbody');
  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="6">${emptyStateHtml('Событий не найдено')}</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map(ev => `
    <tr data-id="${escHtml(ev.id)}" onclick="toggleEventRow(this)">
      <td>${severityBadge(ev.severity)}</td>
      <td><code style="font-size:.8125rem">${escHtml(ev.event_type)}</code></td>
      <td><span class="domain-tag">${escHtml(ev.target_domain)}</span></td>
      <td style="color:var(--text-secondary)">${escHtml(ev.source_type)}</td>
      <td style="color:var(--text-secondary)">${escHtml(truncate(ev.source_name, 32))}</td>
      <td style="color:var(--text-muted);font-size:.8125rem;white-space:nowrap">${fmtDate(ev.detected_at)}</td>
    </tr>
    <tr class="row-detail" id="detail-${escHtml(ev.id)}">
      <td colspan="6" style="padding:.75rem 1rem 1rem 2.5rem">
        <strong style="color:var(--text-secondary);font-size:.8125rem">Payload:</strong>
        <pre class="json-pre">${escHtml(prettyJson(ev.payload))}</pre>
      </td>
    </tr>`).join('');
}

function buildPagination(total) {
  const pages       = Math.ceil(total / PAGE_SIZE) || 1;
  const current     = State.eventsPage;
  const start       = (current - 1) * PAGE_SIZE + 1;
  const end         = Math.min(current * PAGE_SIZE, total);

  document.getElementById('pagination-info').textContent =
    total ? `${start}–${end} из ${total}` : 'Нет данных';

  const ctrl = document.getElementById('pagination-controls');
  const range = buildPageRange(current, pages);
  ctrl.innerHTML = `
    <button class="page-btn" onclick="goToPage(${current - 1})" ${current <= 1 ? 'disabled' : ''}>‹</button>
    ${range.map(p => p === '…'
      ? `<span class="page-btn" style="cursor:default">…</span>`
      : `<button class="page-btn ${p === current ? 'active' : ''}" onclick="goToPage(${p})">${p}</button>`
    ).join('')}
    <button class="page-btn" onclick="goToPage(${current + 1})" ${current >= pages ? 'disabled' : ''}>›</button>`;
}

/** Умный диапазон страниц с многоточием */
function buildPageRange(current, pages) {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  const result = [];
  result.push(1);
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
    severity:   document.getElementById('filter-severity').value,
    event_type: document.getElementById('filter-type').value,
    domain:     document.getElementById('filter-domain').value.trim(),
  };
  loadEventsPage();
}

function clearEventsFilter() {
  document.getElementById('filter-severity').value = '';
  document.getElementById('filter-type').value     = '';
  document.getElementById('filter-domain').value   = '';
  State.eventsFilters = { severity: '', event_type: '', domain: '' };
  State.eventsPage    = 1;
  loadEventsPage();
}

// ─────────────────────────────────────────────
// TAB: Alerts
// ─────────────────────────────────────────────

async function renderAlerts() {
  const container = document.getElementById('alerts-list');
  container.innerHTML = `<div class="loading-skeleton skeleton-line" style="height:60px"></div>`;
  try {
    const alerts = await API.getAlerts();
    State.alertsData = alerts;
    buildAlertsList(alerts);
  } catch (e) {
    Toast.show('error', 'Ошибка загрузки алертов', e.message);
    container.innerHTML = emptyStateHtml('Не удалось загрузить правила');
  }
}

function buildAlertsList(rules) {
  const container = document.getElementById('alerts-list');
  if (!rules.length) {
    container.innerHTML = emptyStateHtml('Правил алертов нет. Создайте первое.');
    return;
  }
  container.innerHTML = rules.map(r => `
    <div class="alert-rule-card" id="rule-${escHtml(r.id)}">
      <div class="alert-rule-info">
        <div class="alert-rule-name">
          ${escHtml(r.name)}
          ${r.is_active ? '<span class="badge badge-success" style="margin-left:.5rem">Active</span>' : '<span class="badge badge-danger" style="margin-left:.5rem">Inactive</span>'}
        </div>
        <div class="alert-rule-meta">
          <span>Min severity: ${severityBadge(r.min_severity)}</span>
          ${r.target_domain ? `<span class="domain-tag">${escHtml(r.target_domain)}</span>` : '<span style="color:var(--text-muted)">Все домены</span>'}
          <span>Chat: <code>${escHtml(r.telegram_chat_id)}</code></span>
          ${r.event_types ? `<span>Types: ${r.event_types.map(t => `<code>${escHtml(t)}</code>`).join(', ')}</span>` : ''}
        </div>
      </div>
      <div class="alert-rule-actions">
        <button class="btn btn-secondary btn-sm" onclick="handleTestAlert('${escHtml(r.id)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 6l3 3 5-5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
          Test
        </button>
        <button class="btn btn-danger btn-sm" onclick="handleDeleteAlert('${escHtml(r.id)}', '${escHtml(r.name)}', this)">
          <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
            <path d="M2 3h8M5 1.5h2M4.5 9.5V5m3 4.5V5M3 3l.7 6.5h4.6L9 3" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"/>
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
  const name       = document.getElementById('alert-name').value.trim();
  const domain     = document.getElementById('alert-domain').value.trim();
  const minSev     = document.getElementById('alert-min-severity').value;
  const chatId     = document.getElementById('alert-chat-id').value.trim();

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
    document.getElementById('create-alert-form').reset();
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

// Загружаем историю сканов из localStorage
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
  const logs = getScanLogs();
  if (!logs.length) {
    container.innerHTML = '<span style="color:var(--text-muted)">Запусков пока не было</span>';
    return;
  }
  container.innerHTML = logs.map(l => {
    const cls = l.status === 'ok' ? 'scan-log-status-ok'
      : l.status === 'error' ? 'scan-log-status-error' : 'scan-log-status-info';
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
  const domain = document.getElementById('scan-domain').value.trim();
  if (!domain) {
    Toast.show('warning', 'Укажите домен');
    return;
  }

  // Собираем выбранные модули
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
// Навигация по табам
// ─────────────────────────────────────────────

const TAB_LOADERS = {
  dashboard: () => { renderDashboard(); startDashboardRefresh(); },
  assets:    () => { stopDashboardRefresh(); renderAssets(); },
  events:    () => { stopDashboardRefresh(); renderEvents(); },
  alerts:    () => { stopDashboardRefresh(); renderAlerts(); },
  scan:      () => { stopDashboardRefresh(); renderScan(); },
};

function switchTab(name) {
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === `tab-${name}`));
  const loader = TAB_LOADERS[name];
  if (loader) loader();
}

// ─────────────────────────────────────────────
// Проверка авторизации при загрузке страницы
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
// Инициализация приложения
// ─────────────────────────────────────────────

function init() {
  if (!checkAuth()) return;

  // Навигация
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
  });

  // Закрытие модалок
  Modal.bindBackdrop('add-asset-modal');

  // Enter в форме логина — отправка
  document.querySelectorAll('.modal input').forEach(inp => {
    inp.addEventListener('keydown', e => {
      if (e.key === 'Enter') e.target.closest('.modal')?.querySelector('.btn-primary')?.click();
    });
  });

  // Фильтры Events — Enter и debounce
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

  // Показываем первый таб
  switchTab('dashboard');
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
  document.getElementById('stealer-drop-zone').classList.remove('drag-over');
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
    infoEl.textContent  = `${_stealerFile.name} — ${mb} МБ`;
    labelEl.innerHTML   = 'Файл выбран. <span style="color:var(--accent);cursor:pointer">Заменить</span>';
    btn.disabled = false;
  } else {
    infoEl.textContent  = '';
    labelEl.innerHTML   = 'Перетащите ZIP / TXT или <span style="color:var(--accent);cursor:pointer">выберите файл</span>';
    btn.disabled = true;
  }
}

async function handleStealerUpload() {
  if (!_stealerFile) {
    Toast.show('warning', 'Выберите файл');
    return;
  }

  const btn       = document.getElementById('stealer-upload-btn');
  const resultEl  = document.getElementById('stealer-result');
  const domainsRaw = document.getElementById('stealer-domains').value.trim();

  setLoading(btn, true);
  resultEl.style.display = 'none';

  try {
    const token = API.getToken();
    const fd    = new FormData();
    fd.append('file', _stealerFile);

    let url = '/api/v1/stealer/upload';
    if (domainsRaw) url += `?domains=${encodeURIComponent(domainsRaw)}`;

    const res = await fetch(url, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
      body: fd,
    });

    if (res.status === 401) {
      API.clearToken();
      window.location.href = '/login.html';
      return;
    }

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || `HTTP ${res.status}`);
    }

    // Успех
    const domains = (data.target_domains || []).join(', ') || '—';
    resultEl.innerHTML = `
      <div style="background:rgba(63,185,80,.08);border:1px solid rgba(63,185,80,.25);
                  border-radius:8px;padding:.875rem 1rem;margin-top:.5rem">
        <div style="color:#3fb950;font-weight:600;margin-bottom:.5rem">
          ✓ Охота запущена — ${escHtml(_stealerFile.name)}
        </div>
        <div style="color:var(--text-secondary);font-size:.8125rem;line-height:1.6">
          Файл: <strong>${escHtml(_stealerFile.name)}</strong>
          (${(_stealerFile.size / 1048576).toFixed(2)} МБ)<br>
          Домены для поиска: <code>${escHtml(domains)}</code><br>
          Парсинг идёт в фоне. Результаты появятся в
          <button class="btn btn-ghost btn-sm" onclick="switchTab('events')"
                  style="padding:0;text-decoration:underline;color:var(--accent)">
            Events → stealer_log
          </button>
        </div>
      </div>`;
    resultEl.style.display = 'block';

    addScanLog('ok', domains, `stealer upload: ${_stealerFile.name}`);
    Toast.show('success', 'Охота запущена', _stealerFile.name);

    // Сбрасываем выбор файла
    _stealerFile = null;
    document.getElementById('stealer-file-input').value = '';
    _updateStealerUI();

  } catch (err) {
    resultEl.innerHTML = `
      <div style="background:rgba(248,81,73,.08);border:1px solid rgba(248,81,73,.25);
                  border-radius:8px;padding:.875rem 1rem;color:#f85149;font-size:.875rem">
        ✗ ${escHtml(err.message)}
      </div>`;
    resultEl.style.display = 'block';
    Toast.show('error', 'Ошибка загрузки', err.message);
  } finally {
    setLoading(btn, false);
  }
}

// Старт после загрузки DOM
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
