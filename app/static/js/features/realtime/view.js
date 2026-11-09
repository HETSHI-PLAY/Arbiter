import {json} from '../../api/client.js';
import {esc, icon, errorState, loadingRows, formatTime} from '../../ui/primitives.js';
import {
  REALTIME_SEVERITY_OPTIONS,
  normalizeSettings,
  parseRealtimeSeverity,
  realtimeSeverityLabel,
  realtimeSeveritySelection,
} from '../settings/model.js';

export async function mount(ctx) {
  const {root, signal, notify} = ctx;
  let settings = null;
  let history = [];
  let timer = null;
  let pulling = false;
  let timePreset = '';
  let customTimeFrom = '';
  let customTimeTo = '';
  let customMaxAlerts = '';

  const TIME_PRESET_LABELS = {
    '': 'Semua waktu (incremental / terbaru)',
    '1h': '1 jam terakhir',
    '24h': '24 jam terakhir',
    '7d': '7 hari terakhir',
    '30d': '30 hari terakhir',
    'custom': 'Rentang kustom…',
  };

  function schedule() {
    clearInterval(timer);
    timer = null;
    if (!settings?.realtime?.enabled) return;
    // Daily mode still polls on a short cadence; the server enforces the 24h gate.
    const seconds = settings.realtime.mode === 'daily'
      ? 300
      : Number(settings.realtime.interval_seconds) || 30;
    timer = setInterval(() => { pull(); }, seconds * 1000);
  }

  function render() {
    const data = settings;
    const realtime = data.realtime;
    const wazuh = data.wazuh;
    const latest = history[0] || null;
    const configured = Boolean(wazuh.indexer_url);
    const modeLabel = realtime.mode === 'daily' ? 'Harian (1× per 24 jam)' : `Setiap ${realtime.interval_seconds} detik`;
    const sevLabel = realtimeSeverityLabel(realtime);
    const sevSelection = realtimeSeveritySelection(realtime);
    const last = latest?.status === 'pulled'
      ? `<strong class="num">${latest.inserted.toLocaleString('id-ID')}</strong> alert baru · ${latest.searched.toLocaleString('id-ID')} diperiksa`
      : latest?.status === 'skipped'
        ? `<span class="inline-status" data-kind="info">Dilewati — pull harian sudah dijalankan</span>`
        : latest
          ? `<span class="inline-status" data-kind="error">${esc(latest.error || 'Pull gagal')}</span>`
          : '<span class="muted">Belum ada pull pada sesi ini.</span>';

    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading">
          <h1>Realtime</h1>
          <p class="page-description">Tarik alert (${esc(sevLabel)}) dari Wazuh Indexer ke database aktif, lalu kelompokkan di AI Triage. Alert yang sama otomatis digabung (dedup) saat masuk.</p>
        </div>
        <div class="page-actions">
          <a class="button" href="#/settings">${icon('settings')} Pengaturan Wazuh</a>
          <a class="button" href="#/ai-triage">${icon('spark')} AI Triage</a>
          <button class="button primary" data-action="pull" type="button" ${pulling || !configured ? 'disabled' : ''}>${icon('refresh')} Pull sekarang</button>
        </div>
      </header>

      ${configured ? '' : `<div class="notice" data-kind="warning"><p><strong>Wazuh Indexer belum dikonfigurasi.</strong> Isi URL dan kredensial di <a href="#/settings">Pengaturan</a> sebelum monitor dapat berjalan.</p></div>`}

      <div class="realtime-grid">
        <section class="form-section realtime-card">
          <h2 class="section-heading">Status monitor</h2>
          <div class="detail-grid">
            <div class="key-value">
              <dt>Status</dt>
              <dd><span class="badge ${realtime.enabled ? 'success' : 'neutral'}"><span class="status-dot"></span>${realtime.enabled ? 'Aktif' : 'Nonaktif'}</span></dd>
              <dd class="meta">${realtime.enabled ? modeLabel : 'Polling otomatis dimatikan'}</dd>
            </div>
            <div class="key-value">
              <dt><label for="realtime-page-severity">Ambang severity</label></dt>
              <dd>
                <select class="select" id="realtime-page-severity" name="realtime_severity">
                  ${REALTIME_SEVERITY_OPTIONS.map(([val, label]) => `<option value="${esc(val)}" ${sevSelection === val ? 'selected' : ''}>${esc(label)}</option>`).join('')}
                </select>
              </dd>
              <dd class="meta">Pilih severity alert yang ditarik saat pull</dd>
            </div>
            <div class="key-value">
              <dt><label for="realtime-time-preset">Rentang waktu telemetri</label></dt>
              <dd>
                <select class="select" id="realtime-time-preset" name="time_preset">
                  <option value="" ${!timePreset ? 'selected' : ''}>Semua waktu</option>
                  <option value="1h" ${timePreset === '1h' ? 'selected' : ''}>1 jam terakhir</option>
                  <option value="24h" ${timePreset === '24h' ? 'selected' : ''}>24 jam terakhir</option>
                  <option value="7d" ${timePreset === '7d' ? 'selected' : ''}>7 hari terakhir</option>
                  <option value="30d" ${timePreset === '30d' ? 'selected' : ''}>30 hari terakhir</option>
                  <option value="custom" ${timePreset === 'custom' ? 'selected' : ''}>Rentang kustom…</option>
                </select>
                <div id="realtime-custom-time" style="display:${timePreset === 'custom' ? 'grid' : 'none'}; grid-template-columns:1fr 1fr; gap:8px; margin-top:10px;">
                  <div class="field">
                    <label for="realtime-time-from">Dari</label>
                    <input class="input" type="datetime-local" id="realtime-time-from" name="time_from" value="${esc(customTimeFrom)}">
                  </div>
                  <div class="field">
                    <label for="realtime-time-to">Sampai</label>
                    <input class="input" type="datetime-local" id="realtime-time-to" name="time_to" value="${esc(customTimeTo)}">
                  </div>
                </div>
              </dd>
              <dd class="meta">Kosongkan "Sampai" untuk menarik hingga waktu saat ini (Now)</dd>
            </div>
            <div class="key-value">
              <dt>Pull terakhir</dt>
              <dd>${latest ? esc(formatTime(latest.at)) : '—'}</dd>
              <dd class="meta">${latest?.duration ? `${latest.duration} ms` : 'Belum ada data'}</dd>
            </div>
            <div class="key-value">
              <dt>Hasil terakhir</dt>
              <dd>${last}</dd>
              <dd class="meta">Filter: ${esc(wazuh.index_pattern || 'wazuh-alerts-*')} · ${esc(sevLabel)} · maks ${realtime.max_alerts} alert/pull</dd>
            </div>
            <div class="key-value">
              <dt>Indexer</dt>
              <dd class="mono" style="font-size:13px; overflow-wrap:anywhere;">${esc(wazuh.indexer_url || 'Belum diatur')}</dd>
              <dd class="meta">${wazuh.password_set ? 'Kredensial tersimpan terenkripsi' : 'Belum ada password tersimpan'}</dd>
            </div>
          </div>
          <div class="settings-actions">
            <button class="button" data-action="toggle" type="button" ${configured ? '' : 'disabled'}>${realtime.enabled ? 'Matikan monitor' : 'Aktifkan monitor'}</button>
          </div>
          <p class="meta">Alert yang ditarik masuk ke database aktif dan muncul di antrean <a href="#/triage">Triage</a>. Untuk mengelompokkan dan klasifikasi TP/FP, buka <a href="#/ai-triage">AI Triage</a>.</p>
        </section>

        <section class="form-section realtime-card">
          <h2 class="section-heading">Riwayat sesi</h2>
          ${history.length ? `<div class="table-region"><table class="data-table"><thead><tr><th>Waktu</th><th>Rentang</th><th>Status</th><th class="numeric">Baru</th><th class="numeric">Dedup</th></tr></thead><tbody>
            ${history.map(item => `<tr>
              <td class="mono">${esc(formatTime(item.at))}</td>
              <td class="mono" style="font-size:12px;">${esc(item.rangeLabel || 'Semua waktu')}</td>
              <td>${item.status === 'pulled' ? `<span class="inline-status" data-kind="success">Pull OK</span>` : item.status === 'skipped' ? `<span class="inline-status" data-kind="info">Dilewati (harian)</span>` : `<span class="inline-status" data-kind="error">${esc(item.error || 'Gagal')}</span>`}</td>
              <td class="numeric num">${item.status === 'pulled' ? item.inserted.toLocaleString('id-ID') : '—'}</td>
              <td class="numeric num">${item.status === 'pulled' ? item.deduplicated.toLocaleString('id-ID') : '—'}</td>
            </tr>`).join('')}
          </tbody></table></div>` : '<p class="muted">Riwayat hanya disimpan di memori halaman ini dan hilang saat berpindah menu atau memuat ulang.</p>'}
        </section>
      </div>`;
  }

  async function pull() {
    if (pulling || !settings?.wazuh?.indexer_url) return;
    pulling = true;
    const started = performance.now();
    const payload = {
      min_rule_level: settings.realtime.min_rule_level,
      max_rule_level: settings.realtime.max_rule_level,
    };
    let rangeLabel = 'Semua waktu';
    const presetMs = {
      '1h': 3600000,
      '24h': 86400000,
      '7d': 604800000,
      '30d': 2592000000,
    }[timePreset];

    if (presetMs) {
      payload.time_from = new Date(Date.now() - presetMs).toISOString();
      rangeLabel = TIME_PRESET_LABELS[timePreset] || timePreset;
    } else if (timePreset === 'custom') {
      const fromInput = root.querySelector('#realtime-time-from');
      const toInput = root.querySelector('#realtime-time-to');
      if (fromInput) customTimeFrom = fromInput.value;
      if (toInput) customTimeTo = toInput.value;
      const fromVal = (customTimeFrom || '').trim();
      const toVal = (customTimeTo || '').trim();
      if (!fromVal && !toVal) {
        pulling = false;
        notify('Pilih minimal tanggal/jam pada kolom "Dari" untuk rentang kustom.', 'warning');
        return;
      }
      if (fromVal) payload.time_from = fromVal;
      if (toVal) payload.time_to = toVal;
      rangeLabel = `${fromVal ? fromVal.replace('T', ' ') : 'Awal'} → ${toVal ? toVal.replace('T', ' ') : 'Sekarang'}`;
    }
    try {
      const result = await json('/api/realtime/pull', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
        signal,
        timeout: 60000,
      });
      history.unshift({
        at: result.pulled_at || new Date().toISOString(),
        status: result.status,
        rangeLabel,
        searched: Number(result.searched) || 0,
        inserted: Number(result.inserted) || 0,
        deduplicated: Number(result.deduplicated) || 0,
        next_pull_at: result.next_pull_at || '',
        duration: Math.round(performance.now() - started),
      });
      if (result.status === 'pulled') {
        notify(`${result.inserted} alert baru ditarik (${result.searched} diperiksa · ${result.deduplicated} dedup).`, 'success');
      } else if (result.status === 'skipped') {
        notify(result.reason || 'Pull harian dilewati.', 'info');
      }
    } catch (error) {
      if (error.name === 'AbortError') return;
      history.unshift({
        at: new Date().toISOString(),
        status: 'error',
        rangeLabel,
        error: error.message,
        duration: Math.round(performance.now() - started),
      });
      notify(error.message, 'error');
    } finally {
      pulling = false;
      history = history.slice(0, 20);
      if (root.isConnected) render();
    }
  }

  async function saveRealtime(changes) {
    const payload = {realtime: {...settings.realtime, ...changes}};
    const body = await json('/api/settings', {
      method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload), signal,
    });
    settings = normalizeSettings(body.settings);
    window.dispatchEvent(new CustomEvent('arbiter:realtime-changed', {detail: settings.realtime}));
    return settings;
  }

  root.addEventListener('change', async event => {
    if (event.target.name === 'time_preset') {
      timePreset = event.target.value;
      const customWrap = root.querySelector('#realtime-custom-time');
      if (customWrap) customWrap.style.display = timePreset === 'custom' ? 'grid' : 'none';
      return;
    }
    if (event.target.name === 'time_from') {
      customTimeFrom = event.target.value;
      return;
    }
    if (event.target.name === 'time_to') {
      customTimeTo = event.target.value;
      return;
    }
    if (event.target.name === 'realtime_severity') {
      const parsed = parseRealtimeSeverity(event.target.value);
      try {
        await saveRealtime({
          min_rule_level: parsed.min_rule_level,
          max_rule_level: parsed.max_rule_level,
        });
        render();
        notify(`Ambang severity realtime diubah ke ${realtimeSeverityLabel(settings.realtime)}.`, 'success');
      } catch (error) {
        if (error.name !== 'AbortError') notify(error.message, 'error');
      }
    }
  }, {signal});

  root.addEventListener('input', event => {
    if (event.target.name === 'time_from') customTimeFrom = event.target.value;
    if (event.target.name === 'time_to') customTimeTo = event.target.value;
  }, {signal});

  root.addEventListener('click', async event => {
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'pull') { await pull(); return; }
    if (action === 'toggle') {
      const button = event.target.closest('[data-action=toggle]');
      button.disabled = true;
      try {
        await saveRealtime({enabled: !settings.realtime.enabled});
        schedule();
        render();
        notify(settings.realtime.enabled ? 'Monitor realtime diaktifkan.' : 'Monitor realtime dimatikan.', settings.realtime.enabled ? 'success' : 'info');
        if (settings.realtime.enabled) await pull();
      } catch (error) {
        if (error.name !== 'AbortError') notify(error.message, 'error');
      } finally {
        if (button.isConnected) button.disabled = false;
      }
    }
  }, {signal});

  root.innerHTML = loadingRows(4);
  try {
    const body = await json('/api/settings', {signal, timeout: 15000});
    settings = normalizeSettings(body.settings);
    render();
    schedule();
    if (settings.realtime.enabled && settings.wazuh.indexer_url) pull();
  } catch (error) {
    if (error.name === 'AbortError') return;
    root.innerHTML = `<header class="page-header"><div class="page-heading"><h1>Realtime</h1></div></header>${errorState('Monitor realtime belum dapat dimuat dari workspace lokal.')}`;
    root.querySelector('[data-action=retry]')?.addEventListener('click', () => { root.innerHTML = loadingRows(4); mount(ctx); }, {signal});
  }

  return () => {
    clearInterval(timer);
    timer = null;
  };
}
