import {json} from '../../api/client.js';
import {esc, icon, errorState, loadingRows} from '../../ui/primitives.js';
import {normalizeSettings, realtimeLabel, wazuhSummary, aiLabel} from './model.js';

export async function mount(ctx) {
  const {root, signal, notify, setGuard} = ctx;
  let settings = null;
  let dirty = false;
  const setDirty = value => { dirty = value; };

  const collect = () => {
    const form = root.querySelector('#settings-form');
    if (!form) return null;
    const data = {
      wazuh: {
        enabled: form.elements.wazuh_enabled.checked,
        indexer_url: form.elements.indexer_url.value.trim(),
        username: form.elements.username.value.trim(),
        index_pattern: form.elements.index_pattern.value.trim() || 'wazuh-alerts-*',
        verify_tls: form.elements.verify_tls.checked,
      },
      realtime: {
        enabled: form.elements.realtime_enabled.checked,
        interval_seconds: Number(form.elements.interval_seconds.value) || 30,
      },
      ai: {
        enabled: form.elements.ai_enabled.checked,
        base_url: form.elements.ai_base_url.value.trim() || 'http://127.0.0.1:11434',
        model: form.elements.ai_model.value.trim(),
        timeout_seconds: Number(form.elements.ai_timeout_seconds.value) || 90,
      },
      ui: {sidebar_default: form.elements.sidebar_default.value},
    };
    const password = form.elements.password.value;
    if (password) data.wazuh.password = password;
    else if (form.elements.clear_password?.checked) data.wazuh.password = '';
    return data;
  };

  const renderStatus = (message, kind = '') => {
    const slot = root.querySelector('#settings-status');
    if (!slot) return;
    slot.textContent = message;
    if (kind) slot.dataset.kind = kind;
    else delete slot.dataset.kind;
  };

  const renderAIStatus = (message, kind = '') => {
    const slot = root.querySelector('#ai-test-status');
    if (!slot) return;
    slot.textContent = message;
    if (kind) slot.dataset.kind = kind;
    else delete slot.dataset.kind;
  };

  async function testConnection(button) {
    const draft = collect();
    if (!draft) return;
    if (!draft.wazuh.indexer_url) { renderStatus('Isi URL Wazuh Indexer terlebih dahulu.', 'error'); return; }
    button.disabled = true;
    renderStatus('Menguji koneksi…');
    try {
      const result = await json('/api/settings/wazuh/test', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(draft.wazuh), signal,
      });
      const count = Number.isInteger(result.count) ? ` · ${result.count.toLocaleString('id-ID')} alert Medium+ (rule.level ≥ ${result.min_rule_level ?? 7})` : '';
      renderStatus(`Terhubung${count}`, 'success');
    } catch (error) {
      if (error.name !== 'AbortError') renderStatus(error.message, 'error');
    } finally {
      button.disabled = false;
    }
  }

  async function testModel(button) {
    const draft = collect();
    if (!draft) return;
    if (!draft.ai.base_url) { renderAIStatus('Isi Base URL Ollama terlebih dahulu.', 'error'); return; }
    if (!draft.ai.model) { renderAIStatus('Isi nama model terlebih dahulu.', 'error'); return; }
    button.disabled = true;
    renderAIStatus('Memeriksa model di Ollama…');
    try {
      await json('/api/ai/test', {
        method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({base_url: draft.ai.base_url, model: draft.ai.model}), signal,
      });
      renderAIStatus('Model tersedia di Ollama.', 'success');
    } catch (error) {
      if (error.name !== 'AbortError') renderAIStatus(error.message, 'error');
    } finally {
      button.disabled = false;
    }
  }

  function render() {
    const data = settings;
    const wazuh = data.wazuh;
    const realtime = data.realtime;
    const ai = data.ai;
    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading">
          <h1>Pengaturan</h1>
          <p class="page-description">Sumber telemetri Wazuh, monitor realtime, dan preferensi tampilan. Password Wazuh dienkripsi dengan kunci lokal sebelum disimpan; API tidak pernah mengembalikannya.</p>
        </div>
      </header>

      <form id="settings-form" class="settings-layout" novalidate>
        <section class="form-section">
          <div class="split">
            <div>
              <h2 class="section-heading">Wazuh Indexer</h2>
              <p class="meta">Koneksi langsung ke Wazuh Indexer (OpenSearch API). Tes koneksi hanya menghitung alert pada indeks — tidak mengunduh atau menyimpan alert. Hanya level <strong>Medium ke atas</strong> (<span class="mono">rule.level ≥ 7</span>) yang dihitung dan nantinya diambil.</p>
            </div>
            <span class="badge ${wazuh.indexer_url ? (wazuh.enabled ? 'success' : 'warning') : 'neutral'}"><span class="status-dot"></span>${esc(wazuh.indexer_url ? (wazuh.enabled ? 'Dikonfigurasi' : 'Nonaktif') : 'Belum diatur')}</span>
          </div>

          <label class="checkbox-label"><input type="checkbox" name="wazuh_enabled" ${wazuh.enabled ? 'checked' : ''}> Aktifkan pengambilan alert dari Wazuh Indexer</label>

          <div class="form-grid">
            <div class="field">
              <label for="indexer-url">URL Indexer</label>
              <input class="input mono" id="indexer-url" name="indexer_url" type="url" inputmode="url" autocomplete="off" spellcheck="false" placeholder="https://wazuh.local:9200" value="${esc(wazuh.indexer_url)}">
              <span class="meta">Hanya http/https. Jangan sertakan path indeks di sini.</span>
            </div>
            <div class="field">
              <label for="index-pattern">Pola indeks</label>
              <input class="input mono" id="index-pattern" name="index_pattern" type="text" autocomplete="off" spellcheck="false" value="${esc(wazuh.index_pattern)}">
              <span class="meta">Contoh: wazuh-alerts-*</span>
            </div>
            <div class="field">
              <label for="indexer-username">Username</label>
              <input class="input" id="indexer-username" name="username" type="text" autocomplete="off" spellcheck="false" value="${esc(wazuh.username)}">
            </div>
            <div class="field">
              <label for="indexer-password">Password</label>
              <input class="input" id="indexer-password" name="password" type="password" autocomplete="new-password" placeholder="${wazuh.password_set ? 'Tersimpan — biarkan kosong untuk mempertahankan' : 'Belum ada password'}">
              ${wazuh.password_set ? '<label class="checkbox-label meta"><input type="checkbox" name="clear_password"> Hapus password tersimpan</label>' : ''}
            </div>
          </div>

          <label class="checkbox-label"><input type="checkbox" name="verify_tls" ${wazuh.verify_tls ? 'checked' : ''}> Verifikasi sertifikat TLS</label>
          <p class="meta">Matikan verifikasi TLS hanya untuk lab lokal dengan sertifikat self-signed.</p>

          <div class="settings-actions">
            <button class="button" type="button" data-action="test-connection">${icon('pulse')} Tes koneksi</button>
            <span class="inline-status" id="settings-status" role="status"></span>
          </div>
        </section>

        <section class="form-section">
          <div class="split">
            <div>
              <h2 class="section-heading">Monitor realtime</h2>
              <p class="meta">Preferensi disimpan sekarang; pengambilan otomatis dari Wazuh Indexer menyusul. Saat aktif nanti, antrean triage akan menyegarkan otomatis dan setiap alert yang kamu triage dicatat sebagai true positive atau false positive.</p>
            </div>
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="realtime-interval">Interval pemeriksaan</label>
              <select class="select" id="realtime-interval" name="interval_seconds">
                ${[15, 30, 60, 120].map(value => `<option value="${value}" ${realtime.interval_seconds === value ? 'selected' : ''}>${value} detik</option>`).join('')}
              </select>
            </div>
            <div class="field">
              <span>Status tombol header</span>
              <label class="checkbox-label"><input type="checkbox" name="realtime_enabled" ${realtime.enabled ? 'checked' : ''}> Tampilkan monitor realtime aktif</label>
              <span class="meta">${esc(realtimeLabel(data))}</span>
            </div>
          </div>
        </section>

        <section class="form-section">
          <div class="split">
            <div>
              <h2 class="section-heading">AI Triage</h2>
              <p class="meta">Klasifikasi True Positive / False Positive memakai model lokal lewat Ollama. Hanya field terstruktur yang sudah disanitasi yang dikirim; raw log, <span class="mono">data</span>, dan <span class="mono">full_log</span> tidak pernah dikirim. Bila model tidak tersedia, Arbiter memakai heuristik deterministik dan memberi label yang jelas.</p>
            </div>
            <span class="badge ${ai.enabled ? 'success' : 'neutral'}"><span class="status-dot"></span>${ai.enabled ? 'AI lokal aktif' : 'Heuristik lokal'}</span>
          </div>

          <label class="checkbox-label"><input type="checkbox" name="ai_enabled" ${ai.enabled ? 'checked' : ''}> Aktifkan klasifikasi AI lokal</label>

          <div class="form-grid">
            <div class="field">
              <label for="ai-base-url">Base URL Ollama</label>
              <input class="input mono" id="ai-base-url" name="ai_base_url" type="url" inputmode="url" autocomplete="off" spellcheck="false" placeholder="http://127.0.0.1:11434" value="${esc(ai.base_url)}">
              <span class="meta">Hanya loopback (localhost / 127.0.0.1 / ::1). Host eksternal ditolak.</span>
            </div>
            <div class="field">
              <label for="ai-model">Model</label>
              <input class="input mono" id="ai-model" name="ai_model" type="text" autocomplete="off" spellcheck="false" value="${esc(ai.model)}">
              <span class="meta">Tag Ollama Hugging Face GGUF.</span>
            </div>
            <div class="field">
              <label for="ai-timeout">Timeout (detik)</label>
              <input class="input" id="ai-timeout" name="ai_timeout_seconds" type="number" min="10" max="180" step="1" value="${esc(ai.timeout_seconds)}">
            </div>
          </div>

          <div class="settings-actions">
            <button class="button" type="button" data-action="test-model">${icon('spark')} Tes model</button>
            <span class="inline-status" id="ai-test-status" role="status"></span>
          </div>
          <p class="meta">${esc(aiLabel(data))}</p>
        </section>

        <section class="form-section">
          <h2 class="section-heading">Tampilan</h2>
          <div class="form-grid">
            <div class="field">
              <label for="sidebar-default">Sidebar saat dibuka</label>
              <select class="select" id="sidebar-default" name="sidebar_default">
                <option value="expanded" ${data.ui.sidebar_default === 'expanded' ? 'selected' : ''}>Terbuka</option>
                <option value="collapsed" ${data.ui.sidebar_default === 'collapsed' ? 'selected' : ''}>Tertutup</option>
              </select>
              <span class="meta">Berlaku sebagai preferensi awal; tombol di header tetap bisa menutup atau membuka kapan saja.</span>
            </div>
          </div>
        </section>

        <div class="settings-footer">
          <span class="meta">${esc(wazuhSummary(data))}</span>
          <button class="button primary" type="submit">${icon('check')} Simpan pengaturan</button>
        </div>
      </form>`;
  }

  async function load() {
    try {
      const body = await json('/api/settings', {signal, timeout: 15000});
      settings = normalizeSettings(body.settings);
      setDirty(false);
      render();
    } catch (error) {
      if (error.name === 'AbortError') return;
      root.innerHTML = `<header class="page-header"><div class="page-heading"><h1>Pengaturan</h1></div></header>${errorState('Pengaturan belum dapat dimuat dari workspace lokal.')}`;
      root.querySelector('[data-action=retry]')?.addEventListener('click', () => { root.innerHTML = loadingRows(4); load(); }, {signal});
    }
  }

  root.addEventListener('input', () => setDirty(true), {signal});
  root.addEventListener('change', event => {
    setDirty(true);
    if (event.target.name === 'realtime_enabled' || event.target.name === 'interval_seconds') {
      const draft = collect();
      if (draft) renderStatus(realtimeLabel(draft), '');
    }
  }, {signal});

  root.addEventListener('click', async event => {
    const connectionButton = event.target.closest('[data-action=test-connection]');
    if (connectionButton) { await testConnection(connectionButton); return; }
    const modelButton = event.target.closest('[data-action=test-model]');
    if (modelButton) { await testModel(modelButton); return; }
  }, {signal});

  root.addEventListener('submit', async event => {
    event.preventDefault();
    const draft = collect();
    if (!draft) return;
    if (draft.wazuh.indexer_url && !/^https?:\/\//i.test(draft.wazuh.indexer_url)) { renderStatus('URL harus diawali http:// atau https://.', 'error'); return; }
    const submit = root.querySelector('#settings-form button[type=submit]');
    submit.disabled = true;
    renderStatus('Menyimpan…');
    try {
      const body = await json('/api/settings', {
        method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(draft), signal,
      });
      settings = normalizeSettings(body.settings);
      setDirty(false);
      render();
      renderStatus('Pengaturan disimpan.', 'success');
      window.dispatchEvent(new CustomEvent('arbiter:settings-saved', {detail: settings}));
      notify('Pengaturan workspace disimpan.', 'success');
    } catch (error) {
      if (error.name !== 'AbortError') renderStatus(error.message, 'error');
    } finally {
      if (submit.isConnected) submit.disabled = false;
    }
  }, {signal});

  setGuard?.(() => !dirty);
  root.innerHTML = loadingRows(4);
  await load();
  return () => {};
}
