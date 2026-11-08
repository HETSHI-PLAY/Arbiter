import {json, copyText} from '../../api/client.js';
import {esc, icon, severity, formatTime, emptyState, errorState, loadingRows} from '../../ui/primitives.js';
import {queryFrom, tenantValues} from '../../state/scope.js';
import {withParams} from '../../router.js';
import {normalizeSettings} from '../settings/model.js';
import {
  GROUP_BY_OPTIONS, MIN_LIMIT, MAX_LIMIT, MIN_LEVELS, REVIEW_STATUSES,
  aiSeverityKey, alertFacts, alertIndex, boundedInteger, formatWibWindowLabel, groupAlerts, modeMeta,
  normalizeTriageResult, numericAlertIds, parseSeveritySelection, summarizeGroups, triageOptions, verdictMeta,
} from './model.js';

export async function mount(ctx) {
  const {root, route, signal, notify} = ctx;
  const routeQuery = queryFrom(route.params);
  const initial = triageOptions(route.params);
  const initialTenants = tenantValues(route.params);
  const state = {
    tenantValue: routeQuery.tenantScope.all ? 'all' : initialTenants.join(','),
    severitySelection: initial.severitySelection,
    limit: initial.limit,
    reviewStatus: initial.reviewStatus,
    groupBy: initial.groupBy,
  };
  let tenantList = [];
  let settings = normalizeSettings(null);
  let result = null;
  let running = false;
  let saving = false;

  const activeTenants = () => {
    if (!state.tenantValue || state.tenantValue === 'all') return ['all'];
    const parts = String(state.tenantValue).split(',').map(item => item.trim()).filter(Boolean);
    return parts.length ? parts : ['all'];
  };

  const activeTenantLabel = () => {
    const list = activeTenants();
    if (list.length === 1 && list[0] === 'all') return 'Semua tenant';
    return list.join(', ');
  };

  const scopedRoute = (path, extra = {}, overrideTenant = '') => {
    const params = new URLSearchParams();
    const tenants = overrideTenant && overrideTenant !== 'Default' ? [overrideTenant] : activeTenants();
    for (const tenant of tenants) params.append('tenant', tenant);
    for (const [key, value] of Object.entries(extra)) {
      if (value === undefined || value === null || value === '') params.delete(key);
      else params.set(key, String(value));
    }
    return withParams(path, params);
  };

  function tenantOptionsHTML() {
    const known = new Map();
    for (const row of tenantList) {
      const name = String(row?.tenant || '').trim();
      if (name) known.set(name, row?.count);
    }
    for (const name of routeQuery.tenantScope.tenants) {
      if (name && !known.has(name)) known.set(name, undefined);
    }
    const multiScopeOption = routeQuery.tenantScope.tenants.length > 1
      ? `<option value="${esc(routeQuery.tenantScope.tenants.join(','))}" ${state.tenantValue === routeQuery.tenantScope.tenants.join(',') ? 'selected' : ''}>${esc(routeQuery.tenantScope.label)}</option>`
      : '';
    const options = [...known.entries()].map(([name, count]) => {
      const countText = Number.isFinite(Number(count)) ? ` (${Number(count).toLocaleString('id-ID')})` : '';
      return `<option value="${esc(name)}" ${state.tenantValue === name ? 'selected' : ''}>${esc(name)}${countText}</option>`;
    }).join('');
    return `<option value="all" ${state.tenantValue === 'all' ? 'selected' : ''}>Semua tenant</option>${multiScopeOption}${options}`;
  }

  function renderControls() {
    const ai = settings.ai;
    return `
      <form class="ai-controls" id="ai-triage-form">
        <div class="field">
          <label for="ai-tenant">Tenant</label>
          <select class="select" id="ai-tenant" name="tenant">
            ${tenantOptionsHTML()}
          </select>
        </div>
        <div class="field">
          <label for="ai-min-level">Ambang severity</label>
          <select class="select" id="ai-min-level" name="min_rule_level">
            ${MIN_LEVELS.map(([value, label]) => `<option value="${esc(value)}" ${String(state.severitySelection) === String(value) ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
        </div>
        <div class="field">
          <label for="ai-limit">Maksimum alert</label>
          <input class="input" id="ai-limit" name="limit" type="number" min="${MIN_LIMIT}" max="${MAX_LIMIT}" step="1" value="${esc(state.limit)}" placeholder="40" required>
        </div>
        <div class="field">
          <label for="ai-review-status">Status review</label>
          <select class="select" id="ai-review-status" name="review_status">
            ${REVIEW_STATUSES.map(([value, label]) => `<option value="${value}" ${state.reviewStatus === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
        </div>
        <div class="field">
          <label for="ai-group-by">Dasar pengelompokan</label>
          <select class="select" id="ai-group-by" name="group_by">
            ${GROUP_BY_OPTIONS.map(([value, label]) => `<option value="${esc(value)}" ${state.groupBy === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
        </div>
        <div class="field ai-run-field">
          <span class="meta">${ai.enabled ? `Model ${esc(ai.model)}` : 'Mode heuristik lokal'}</span>
          <button class="button primary" type="submit" ${running ? 'disabled' : ''}>${icon('spark')} ${running ? 'Memproses…' : 'Jalankan AI Triage'}</button>
        </div>
      </form>`;
  }

  function renderIntro() {
    const ai = settings.ai;
    if (!ai.enabled) {
      return `<div class="notice" data-kind="warning"><p><strong>AI lokal belum diaktifkan.</strong> Hasil di bawah memakai heuristik deterministik dan diberi label jelas. Untuk klasifikasi model, aktifkan AI Triage di <a href="#/settings">Pengaturan</a>.</p></div>`;
    }
    return `<div class="notice" data-kind="info"><p><strong>Mode AI lokal.</strong> Hanya field terstruktur yang sudah disanitasi yang dikirim ke <span class="mono">${esc(ai.base_url)}</span>. Raw log, <span class="mono">data</span>, dan <span class="mono">full_log</span> tidak pernah dikirim. Verifikasi tetap dilakukan oleh analis.</p></div>`;
  }

  function renderSummary(data, counts, mode) {
    const meta = modeMeta(mode);
    const levelLabel = Number.isInteger(data.maxRuleLevel)
      ? `${data.minRuleLevel}–${data.maxRuleLevel}`
      : `≥ ${data.minRuleLevel}`;
    return `
      <section class="ai-summary" aria-label="Ringkasan hasil triage">
        <div class="ai-summary-head">
          <div>
            <span class="badge ${meta.badge}">${esc(meta.label)}</span>
            <span class="meta">${data.alertCount.toLocaleString('id-ID')} alert · rule.level ${levelLabel}</span>
          </div>
          <span class="meta">${data.model ? `Model ${esc(data.model)}` : 'Tanpa model eksternal'}</span>
        </div>
        <div class="ai-stats">
          <div class="ai-stat"><span class="meta">True Positive</span><strong class="num">${counts.tp.toLocaleString('id-ID')}</strong><span class="meta">grup</span></div>
          <div class="ai-stat"><span class="meta">False Positive</span><strong class="num">${counts.fp.toLocaleString('id-ID')}</strong><span class="meta">grup</span></div>
          <div class="ai-stat"><span class="meta">Perlu ditinjau</span><strong class="num">${counts.needs_review.toLocaleString('id-ID')}</strong><span class="meta">grup</span></div>
          <div class="ai-stat"><span class="meta">Alert tergrup</span><strong class="num">${counts.alertCount.toLocaleString('id-ID')}</strong><span class="meta">dari ${data.alertCount.toLocaleString('id-ID')}</span></div>
        </div>
      </section>`;
  }

  function renderAlertTable(group, index) {
    const records = groupAlerts(group, index);
    if (!records.length) return '<p class="meta">Tidak ada detail alert yang dapat ditampilkan.</p>';
    return `
      <div class="table-region ai-alert-table">
        <table class="data-table">
          <thead><tr><th>Severity</th><th>Waktu</th><th>Agent / sumber</th><th>Alert</th><th class="numeric">Hits</th></tr></thead>
          <tbody>
            ${records.map(alert => {
              const facts = alertFacts(alert);
              return `<tr>
                <td>${severity(aiSeverityKey(alert.rule_level))}</td>
                <td class="mono">${esc(formatTime(alert.timestamp))}</td>
                <td><span class="mono">${esc(alert.agent_name || '—')}</span>${alert.source_ip ? `<br><span class="meta mono">${esc(alert.source_ip)}</span>` : ''}</td>
                <td><span class="ai-alert-desc">${esc(alert.description || 'Tanpa deskripsi')}</span>${facts.length ? `<br><span class="meta">${esc(facts.join(' · '))}</span>` : ''}</td>
                <td class="numeric num">${Number(alert.hit_count || 1).toLocaleString('id-ID')}</td>
              </tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>`;
  }

  function renderGroup(group, index, position) {
    const meta = verdictMeta(group.verdict);
    const records = groupAlerts(group, index);
    const first = records[0];
    const groupTenant = String(group.tenant || first?.tenant || '').trim();
    const winLabel = formatWibWindowLabel(group.windowKey);
    const newCount = Array.isArray(group.newAlertIds) ? group.newAlertIds.length : 0;
    const incidentIds = numericAlertIds(group, index);
    const alertsHref = incidentIds.length
      ? scopedRoute('/triage', {alert_ids: incidentIds.join(','), review_status: 'all', alert: first?.id}, groupTenant)
      : first
        ? scopedRoute('/triage', {alert: first.id}, groupTenant)
        : scopedRoute('/triage', {}, groupTenant);
    const incidentHref = incidentIds.length ? scopedRoute('/incidents/new', {alert_ids: incidentIds.join(',')}, groupTenant) : '';
    return `
      <article class="ai-group" aria-labelledby="ai-group-${position}">
        <div class="ai-group-head">
          <div>
            <span class="meta">${esc(group.category)}${groupTenant ? ` · Tenant ${esc(groupTenant)}` : ''}${winLabel ? ` · Batas grup ${esc(winLabel)}` : ''}</span>
            <h3 id="ai-group-${position}">${esc(group.title)}</h3>
          </div>
          <div>
            ${newCount > 0 ? `<span class="badge success">+${newCount.toLocaleString('id-ID')} alert baru</span> ` : ''}
            ${group.savedGroupId ? `<a class="badge neutral" href="#/incidents/${esc(group.savedGroupId)}">Tersimpan di Insiden</a> ` : ''}
            <span class="badge ${meta.badge}">${esc(meta.label)}</span>
          </div>
        </div>
        <p class="ai-group-reason">${esc(group.reason)}</p>
        <div class="ai-group-meta">
          <span class="meta">${records.length.toLocaleString('id-ID')} alert dalam grup</span>
          <span class="meta">${esc(meta.description)}</span>
        </div>
        <details class="ai-group-details">
          <summary class="button">${icon('cases')} Lihat ${records.length.toLocaleString('id-ID')} alert lengkap</summary>
          ${renderAlertTable(group, index)}
        </details>
        <div class="ai-group-actions">
          <a class="button" href="${alertsHref}">${icon('arrow')} Buka di Triage</a>
          <button class="button" type="button" data-action="copy-group-logs" data-group-index="${position}">${icon('copy')} Salin full log (${records.length})</button>
          ${incidentHref
            ? `<a class="button primary" href="${incidentHref}">${icon('plus')} Siapkan insiden (${incidentIds.length})</a>`
            : '<button class="button" type="button" disabled>Siapkan insiden</button>'}
        </div>
      </article>`;
  }

  function renderResult() {
    if (!result) {
      return emptyState(
        'Belum ada hasil triage',
        'Jalankan AI Triage untuk mengelompokkan alert Medium ke atas dan menyiapkan klasifikasi True Positive, False Positive, atau Perlu ditinjau.',
        `<button class="button primary" type="button" data-action="run-inline">${icon('spark')} Jalankan AI Triage</button>`,
      );
    }
    const counts = summarizeGroups(result.groups);
    return `
      ${result.warning ? `<div class="notice" data-kind="warning"><p>${esc(result.warning)}</p></div>` : ''}
      ${renderSummary(result, counts, result.mode)}
      ${result.groups.length
        ? `<div class="ai-save-bar"><button class="button primary" type="button" data-action="save" ${saving ? 'disabled' : ''}>${icon('cases')} ${saving ? 'Menyimpan…' : 'Simpan ke Insiden'}</button><span class="inline-status" id="ai-save-status" role="status"></span></div>
           <div class="ai-groups">${result.groups.map((group, index) => renderGroup(group, alertIndex(result.alerts), index)).join('')}</div>`
        : emptyState('Tidak ada alert pada scope ini', 'Ubah status review, ambang severity, atau scope tenant lalu jalankan ulang.')}`;
  }

  function render() {
    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading">
          <h1>AI Triage</h1>
          <p class="page-description">Klasifikasi True Positive / False Positive dan pengelompokan alert Wazuh Medium ke atas. AI berjalan lokal lewat Ollama; bila model tidak tersedia, Arbiter memakai heuristik deterministik dan memberi label yang jelas.</p>
        </div>
        <div class="page-actions">
          <a class="button" href="#/settings">${icon('settings')} Pengaturan AI</a>
        </div>
      </header>

      <div class="ai-layout">
        <section class="form-section">
          <div class="split">
            <div>
              <h2 class="section-heading">Jalankan triage</h2>
              <p class="meta">Scope tenant: <strong id="ai-tenant-label">${esc(activeTenantLabel())}</strong>. Halaman ini tidak mengubah status review atau menyimpan alert baru.</p>
            </div>
            <span class="badge ${settings.ai.enabled ? 'success' : 'warning'}"><span class="status-dot"></span>${settings.ai.enabled ? 'AI lokal aktif' : 'Heuristik lokal'}</span>
          </div>
          ${renderIntro()}
          ${renderControls()}
          <span class="inline-status" id="ai-status" role="status"></span>
        </section>

        <section class="form-section" id="ai-results" aria-live="polite">
          <h2 class="section-heading">Hasil</h2>
          ${renderResult()}
        </section>
      </div>`;
  }

  async function run() {
    if (running) return;
    const form = root.querySelector('#ai-triage-form');
    if (!form) return;
    const tenantField = form.elements.tenant?.value || state.tenantValue || 'all';
    const limit = boundedInteger(form.elements.limit.value, 40, MIN_LIMIT, MAX_LIMIT);
    const parsedLevel = parseSeveritySelection(form.elements.min_rule_level.value);
    const minRuleLevel = parsedLevel.minRuleLevel;
    const maxRuleLevel = parsedLevel.maxRuleLevel;
    const reviewStatus = form.elements.review_status.value;
    const groupBy = form.elements.group_by?.value || state.groupBy || 'rule_description';
    state.tenantValue = tenantField;
    state.limit = limit;
    state.severitySelection = parsedLevel.selection;
    state.reviewStatus = reviewStatus;
    state.groupBy = groupBy;
    running = true;
    const button = form.querySelector('button[type=submit]');
    const status = root.querySelector('#ai-status');
    if (button) button.disabled = true;
    if (button) button.innerHTML = `${icon('spark')} Memproses…`;
    if (status) { status.textContent = 'Mengelompokkan alert dan menghitung klasifikasi…'; status.dataset.kind = 'info'; }
    try {
      const body = await json('/api/ai/triage', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          tenant: activeTenants(),
          limit,
          min_rule_level: minRuleLevel,
          max_rule_level: maxRuleLevel,
          review_status: reviewStatus,
          group_by: groupBy,
        }),
        signal,
        timeout: Math.max(120000, (Number(settings.ai.timeout_seconds) || 90) * 1000),
      });
      result = normalizeTriageResult(body);
      running = false;
      render();
      const counts = summarizeGroups(result.groups);
      notify(`${result.alertCount} alert diproses · ${counts.tp} TP · ${counts.fp} FP · ${counts.needs_review} perlu ditinjau.`, result.mode === 'local_rules_fallback' ? 'warning' : 'success');
    } catch (error) {
      if (error.name === 'AbortError') return;
      running = false;
      if (root.querySelector('#ai-triage-form')) {
        const currentButton = root.querySelector('#ai-triage-form button[type=submit]');
        if (currentButton) { currentButton.disabled = false; currentButton.innerHTML = `${icon('spark')} Jalankan AI Triage`; }
      }
      if (status) { status.textContent = error.message; status.dataset.kind = 'error'; }
    }
  }

  async function copyGroupLogs(group, index) {
    const ids = numericAlertIds(group, index);
    if (!ids.length) { notify('Grup ini tidak punya alert dengan ID valid untuk disalin.', 'error'); return; }
    const params = new URLSearchParams();
    for (const tenant of activeTenants()) params.append('tenant', tenant);
    const status = root.querySelector('#ai-status');
    if (status) { status.textContent = `Mengambil ${ids.length} full log…`; status.dataset.kind = 'info'; }
    try {
      const body = await json(`/api/alerts/full-logs?${params}`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({alert_ids: ids}),
        signal,
        timeout: 30000,
      });
      const items = Array.isArray(body.items) ? body.items : [];
      const text = items.map(a => {
        const head = `Alert #${a.id} · ${a.description || 'Tanpa deskripsi'} · Sumber ${a.source_ip || '—'} · Rule ${a.rule_id || '—'}`;
        return `${head}\n${a.full_log || '(full log tidak tersedia)'}`;
      }).join('\n\n---\n\n');
      if (!text) { notify('Tidak ada full log yang dapat disalin.', 'error'); return; }
      await copyText(text);
      if (status) { status.textContent = `${items.length} full log disalin ke clipboard.`; status.dataset.kind = 'success'; }
      notify(`${items.length} full log disalin.`, 'success');
    } catch (error) {
      if (error.name === 'AbortError') return;
      if (status) { status.textContent = error.message; status.dataset.kind = 'error'; }
    }
  }

  async function save() {
    if (saving || !result?.groups?.length) return;
    saving = true;
    const status = root.querySelector('#ai-save-status');
    const button = root.querySelector('[data-action=save]');
    if (button) button.disabled = true;
    if (status) { status.textContent = 'Menyimpan grup ke Insiden…'; status.dataset.kind = 'info'; }
    try {
      const body = await json('/api/ai/triage/save', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          tenant: activeTenants(),
          groups: result.groups.map(group => ({
            title: group.title,
            category: group.category,
            verdict: group.verdict,
            reason: group.reason,
            alert_ids: group.alertIds,
            window_key: group.windowKey || '',
          })),
        }),
        signal,
        timeout: 30000,
      });
      saving = false;
      if (status) { status.textContent = `${body.count} grup tersimpan. Buka halaman Insiden untuk menambah/mengurangi alert.`; status.dataset.kind = 'success'; }
      if (button) { button.disabled = false; button.innerHTML = `${icon('cases')} Simpan ke Insiden`; }
      notify(`${body.count} grup triage tersimpan ke Insiden.`, 'success');
    } catch (error) {
      if (error.name === 'AbortError') return;
      saving = false;
      if (status) { status.textContent = error.message; status.dataset.kind = 'error'; }
      if (button) { button.disabled = false; button.innerHTML = `${icon('cases')} Simpan ke Insiden`; }
    }
  }

  root.addEventListener('change', event => {
    const form = root.querySelector('#ai-triage-form');
    if (!form || !form.contains(event.target)) return;
    if (event.target.name === 'tenant') {
      state.tenantValue = event.target.value || 'all';
      const label = root.querySelector('#ai-tenant-label');
      if (label) label.textContent = activeTenantLabel();
    } else if (event.target.name === 'min_rule_level') {
      state.severitySelection = parseSeveritySelection(event.target.value).selection;
    } else if (event.target.name === 'limit') {
      state.limit = boundedInteger(event.target.value, 40, MIN_LIMIT, MAX_LIMIT);
    } else if (event.target.name === 'review_status') {
      state.reviewStatus = event.target.value;
    } else if (event.target.name === 'group_by') {
      state.groupBy = event.target.value;
    }
  }, {signal});

  root.addEventListener('submit', event => {
    if (event.target.id !== 'ai-triage-form') return;
    event.preventDefault();
    run();
  }, {signal});

  root.addEventListener('click', event => {
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'run-inline') run();
    if (action === 'save') save();
    if (action === 'copy-group-logs') {
      const position = Number(event.target.closest('[data-action=copy-group-logs]')?.dataset.groupIndex);
      const group = result?.groups?.[position];
      if (group) copyGroupLogs(group, alertIndex(result.alerts));
    }
  }, {signal});

  root.innerHTML = loadingRows(4);
  try {
    const [settingsBody, tenantsBody, savedTriage] = await Promise.all([
      json('/api/settings', {signal, timeout: 15000}),
      json('/api/tenants', {signal, timeout: 10000}).catch(() => ({tenants: []})),
      json('/api/ai/triage', {signal, timeout: 20000}).catch(() => ({saved: false, result: null})),
    ]);
    settings = normalizeSettings(settingsBody.settings);
    tenantList = Array.isArray(tenantsBody?.tenants) ? tenantsBody.tenants : [];
    if (savedTriage?.saved && savedTriage.result) {
      result = normalizeTriageResult(savedTriage.result);
      const savedOpts = triageOptions(savedTriage.options || {});
      const getParam = key => route.params?.get ? route.params.get(key) : route.params?.[key];
      if (!getParam('tenant') && Array.isArray(savedTriage.options?.tenant) && savedTriage.options.tenant.length) {
        state.tenantValue = savedTriage.options.tenant.includes('all') ? 'all' : savedTriage.options.tenant.join(',');
      }
      if (!getParam('min_rule_level')) state.severitySelection = savedOpts.severitySelection;
      if (!getParam('limit')) state.limit = savedOpts.limit;
      if (!getParam('review_status')) state.reviewStatus = savedOpts.reviewStatus;
      if (!getParam('group_by')) state.groupBy = savedOpts.groupBy;
    }
    render();
  } catch (error) {
    if (error.name === 'AbortError') return;
    root.innerHTML = `<header class="page-header"><div class="page-heading"><h1>AI Triage</h1></div></header>${errorState('Preferensi AI belum dapat dimuat dari workspace lokal.')}`;
    root.querySelector('[data-action=retry]')?.addEventListener('click', () => { root.innerHTML = loadingRows(4); mount(ctx); }, {signal});
  }

  return () => {};
}
