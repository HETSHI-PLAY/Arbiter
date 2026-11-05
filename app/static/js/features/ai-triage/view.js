import {json} from '../../api/client.js';
import {esc, icon, severity, formatTime, emptyState, errorState, loadingRows} from '../../ui/primitives.js';
import {queryFrom, tenantValues} from '../../state/scope.js';
import {withParams} from '../../router.js';
import {normalizeSettings} from '../settings/model.js';
import {
  LIMITS, MIN_LEVELS, REVIEW_STATUSES,
  alertFacts, alertIndex, boundedInteger, groupAlerts, modeMeta,
  normalizeTriageResult, numericAlertIds, summarizeGroups, triageOptions, verdictMeta,
} from './model.js';

const MAX_VISIBLE_ALERTS = 100;

export async function mount(ctx) {
  const {root, route, signal, notify} = ctx;
  const routeQuery = queryFrom(route.params);
  const initial = triageOptions(route.params);
  let settings = normalizeSettings(null);
  let result = null;
  let running = false;
  let saving = false;

  const scopedRoute = (path, extra = {}) => {
    const params = new URLSearchParams();
    for (const tenant of tenantValues(route.params)) params.append('tenant', tenant);
    for (const [key, value] of Object.entries(extra)) {
      if (value === undefined || value === null || value === '') params.delete(key);
      else params.set(key, String(value));
    }
    return withParams(path, params);
  };

  function renderControls() {
    const ai = settings.ai;
    return `
      <form class="ai-controls" id="ai-triage-form">
        <div class="field">
          <label for="ai-min-level">Ambang severity</label>
          <select class="select" id="ai-min-level" name="min_rule_level">
            ${MIN_LEVELS.map(([value, label]) => `<option value="${value}" ${initial.minRuleLevel === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
          </select>
        </div>
        <div class="field">
          <label for="ai-limit">Maksimum alert</label>
          <select class="select" id="ai-limit" name="limit">
            ${LIMITS.map(value => `<option value="${value}" ${initial.limit === value ? 'selected' : ''}>${value} alert</option>`).join('')}
          </select>
        </div>
        <div class="field">
          <label for="ai-review-status">Status review</label>
          <select class="select" id="ai-review-status" name="review_status">
            ${REVIEW_STATUSES.map(([value, label]) => `<option value="${value}" ${initial.reviewStatus === value ? 'selected' : ''}>${esc(label)}</option>`).join('')}
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
    return `
      <section class="ai-summary" aria-label="Ringkasan hasil triage">
        <div class="ai-summary-head">
          <div>
            <span class="badge ${meta.badge}">${esc(meta.label)}</span>
            <span class="meta">${data.alertCount.toLocaleString('id-ID')} alert · rule.level ≥ ${data.minRuleLevel}</span>
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
                <td>${severity(alert.rule_level)}</td>
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
    const incidentIds = numericAlertIds(group, index);
    const alertsHref = first ? scopedRoute('/triage', {alert: first.id}) : scopedRoute('/triage');
    const incidentHref = incidentIds.length ? scopedRoute('/incidents/new', {alert_ids: incidentIds.join(',')}) : '';
    return `
      <article class="ai-group" aria-labelledby="ai-group-${position}">
        <div class="ai-group-head">
          <div>
            <span class="meta">${esc(group.category)}</span>
            <h3 id="ai-group-${position}">${esc(group.title)}</h3>
          </div>
          <span class="badge ${meta.badge}">${esc(meta.label)}</span>
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
              <p class="meta">Scope tenant mengikuti workspace: <strong>${esc(routeQuery.tenantScope.label)}</strong>. Halaman ini tidak mengubah status review atau menyimpan alert baru.</p>
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
    const limit = boundedInteger(form.elements.limit.value, 40, 5, 100);
    const minRuleLevel = boundedInteger(form.elements.min_rule_level.value, 7, 0, 15);
    const reviewStatus = form.elements.review_status.value;
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
          tenant: tenantValues(route.params),
          limit,
          min_rule_level: minRuleLevel,
          review_status: reviewStatus,
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
          tenant: tenantValues(route.params),
          groups: result.groups.map(group => ({
            title: group.title,
            category: group.category,
            verdict: group.verdict,
            reason: group.reason,
            alert_ids: group.alertIds,
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

  root.addEventListener('submit', event => {
    if (event.target.id !== 'ai-triage-form') return;
    event.preventDefault();
    run();
  }, {signal});

  root.addEventListener('click', event => {
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'run-inline') run();
    if (action === 'save') save();
  }, {signal});

  root.innerHTML = loadingRows(4);
  try {
    const body = await json('/api/settings', {signal, timeout: 15000});
    settings = normalizeSettings(body.settings);
    render();
  } catch (error) {
    if (error.name === 'AbortError') return;
    root.innerHTML = `<header class="page-header"><div class="page-heading"><h1>AI Triage</h1></div></header>${errorState('Preferensi AI belum dapat dimuat dari workspace lokal.')}`;
    root.querySelector('[data-action=retry]')?.addEventListener('click', () => { root.innerHTML = loadingRows(4); mount(ctx); }, {signal});
  }

  return () => {};
}
