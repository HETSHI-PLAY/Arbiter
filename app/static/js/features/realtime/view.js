import {json} from '../../api/client.js';
import {esc, icon, errorState, loadingRows, formatTime} from '../../ui/primitives.js';
import {normalizeSettings} from '../settings/model.js';

const INTERVALS = [15, 30, 60, 120, 300];

export async function mount(ctx) {
  const {root, signal, notify} = ctx;
  let settings = null;
  let history = [];
  let timer = null;
  let checking = false;

  function schedule() {
    clearInterval(timer);
    timer = null;
    if (settings?.realtime?.enabled) {
      const seconds = Number(settings.realtime.interval_seconds) || 30;
      timer = setInterval(() => { check(); }, seconds * 1000);
    }
  }

  function render() {
    const data = settings;
    const realtime = data.realtime;
    const wazuh = data.wazuh;
    const latest = history[0] || null;
    const configured = Boolean(wazuh.indexer_url);
    const last = latest?.ok
      ? `<strong class="num">${latest.count.toLocaleString('id-ID')}</strong> alert Medium+`
      : latest
        ? `<span class="inline-status" data-kind="error">${esc(latest.error || 'Pemeriksaan gagal')}</span>`
        : '<span class="muted">Belum ada pemeriksaan pada sesi ini.</span>';

    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading">
          <h1>Realtime</h1>
          <p class="page-description">Monitor jumlah alert Wazuh Medium+ (rule.level ≥ 7) secara berkala. Halaman ini hanya menghitung — alert tidak diunduh atau disimpan.</p>
        </div>
        <div class="page-actions">
          <a class="button" href="#/settings">${icon('settings')} Pengaturan Wazuh</a>
          <button class="button primary" data-action="check" type="button" ${checking || !configured ? 'disabled' : ''}>${icon('refresh')} Periksa sekarang</button>
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
              <dd class="meta">${realtime.enabled ? `Memeriksa setiap ${realtime.interval_seconds} detik` : 'Polling otomatis dimatikan'}</dd>
            </div>
            <div class="key-value">
              <dt>Pemeriksaan terakhir</dt>
              <dd>${latest ? esc(formatTime(latest.at)) : '—'}</dd>
              <dd class="meta">${latest?.duration ? `${latest.duration} ms` : 'Belum ada data'}</dd>
            </div>
            <div class="key-value">
              <dt>Jumlah terakhir</dt>
              <dd>${last}</dd>
              <dd class="meta">Filter: ${esc(wazuh.index_pattern || 'wazuh-alerts-*')} · rule.level ≥ 7</dd>
            </div>
            <div class="key-value">
              <dt>Indexer</dt>
              <dd class="mono" style="font-size:13px; overflow-wrap:anywhere;">${esc(wazuh.indexer_url || 'Belum diatur')}</dd>
              <dd class="meta">${wazuh.password_set ? 'Kredensial tersimpan terenkripsi' : 'Belum ada password tersimpan'}</dd>
            </div>
          </div>
          <div class="settings-actions">
            <button class="button" data-action="toggle" type="button" ${configured ? '' : 'disabled'}>${realtime.enabled ? 'Matikan monitor' : 'Aktifkan monitor'}</button>
            <div class="field" style="max-width:220px;">
              <label for="realtime-interval">Interval</label>
              <select class="select" id="realtime-interval" ${realtime.enabled ? '' : 'disabled'}>
                ${INTERVALS.map(value => `<option value="${value}" ${Number(realtime.interval_seconds) === value ? 'selected' : ''}>${value} detik</option>`).join('')}
              </select>
            </div>
          </div>
          <p class="meta">Monitor ini tidak menarik alert. Untuk AI Triage dan pengelompokan alert, buka menu <a href="#/ai-triage">AI Triage</a>.</p>
        </section>

        <section class="form-section realtime-card">
          <h2 class="section-heading">Riwayat sesi</h2>
          ${history.length ? `<div class="table-region"><table class="data-table"><thead><tr><th>Waktu</th><th class="numeric">Medium+</th><th>Hasil</th></tr></thead><tbody>
            ${history.map(item => `<tr>
              <td class="mono">${esc(formatTime(item.at))}</td>
              <td class="numeric num">${item.ok ? item.count.toLocaleString('id-ID') : '—'}</td>
              <td>${item.ok ? `<span class="inline-status" data-kind="success">OK · ${item.duration} ms</span>` : `<span class="inline-status" data-kind="error">${esc(item.error || 'Gagal')}</span>`}</td>
            </tr>`).join('')}
          </tbody></table></div>` : '<p class="muted">Riwayat hanya disimpan di memori halaman ini dan hilang saat berpindah menu atau memuat ulang.</p>'}
        </section>
      </div>`;
  }

  async function check() {
    if (checking || !settings?.wazuh?.indexer_url) return;
    checking = true;
    const started = performance.now();
    try {
      const result = await json('/api/realtime/count', {signal, timeout: 15000});
      history.unshift({
        at: result.checked_at || new Date().toISOString(),
        ok: true,
        count: Number(result.count) || 0,
        duration: Math.round(performance.now() - started),
      });
    } catch (error) {
      if (error.name === 'AbortError') return;
      history.unshift({
        at: new Date().toISOString(),
        ok: false,
        error: error.message,
        duration: Math.round(performance.now() - started),
      });
    } finally {
      checking = false;
      history = history.slice(0, 20);
      if (root.isConnected) render();
    }
  }

  function saveRealtime(changes) {
    const payload = {realtime: {...settings.realtime, ...changes}};
    return json('/api/settings', {
      method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload), signal,
    }).then(body => {
      settings = normalizeSettings(body.settings);
      window.dispatchEvent(new CustomEvent('arbiter:realtime-changed', {detail: settings.realtime}));
      return settings;
    });
  }

  root.addEventListener('click', async event => {
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'check') { await check(); return; }
    if (action === 'toggle') {
      const button = event.target.closest('[data-action=toggle]');
      button.disabled = true;
      try {
        await saveRealtime({enabled: !settings.realtime.enabled});
        schedule();
        render();
        notify(settings.realtime.enabled ? 'Monitor realtime diaktifkan.' : 'Monitor realtime dimatikan.', settings.realtime.enabled ? 'success' : 'info');
        if (settings.realtime.enabled) await check();
      } catch (error) {
        if (error.name !== 'AbortError') notify(error.message, 'error');
      } finally {
        if (button.isConnected) button.disabled = false;
      }
    }
  }, {signal});

  root.addEventListener('change', async event => {
    if (event.target.id !== 'realtime-interval') return;
    const interval = Number(event.target.value);
    try {
      await saveRealtime({interval_seconds: interval});
      schedule();
      render();
      notify(`Interval realtime diubah ke ${interval} detik.`, 'success');
    } catch (error) {
      if (error.name !== 'AbortError') notify(error.message, 'error');
    }
  }, {signal});

  root.innerHTML = loadingRows(4);
  try {
    const body = await json('/api/settings', {signal, timeout: 15000});
    settings = normalizeSettings(body.settings);
    render();
    schedule();
    if (settings.realtime.enabled && settings.wazuh.indexer_url) check();
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
