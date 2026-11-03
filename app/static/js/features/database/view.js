import {json, apiURL} from '../../api/client.js';
import {esc, icon, emptyState, errorState, loadingRows, formatTime} from '../../ui/primitives.js';
import {summarizeTelemetryRange, databaseIdentity} from './model.js';

export async function mount(ctx) {
  const {root, route, signal, notify, navigate} = ctx;
  let statusData = null, testResults = {};
  let uriDraft = '';
  let switchUnverified = false;
  let previews = {}, previewVersion = 0;
  const invalidatePreviews = () => { previews = {}; previewVersion++; };
  root.addEventListener('change', invalidatePreviews, {signal});
  ctx.setGuard?.(() => !uriDraft.trim());
  root.addEventListener('input', () => { uriDraft = root.querySelector('#remote-url-input')?.value || ''; invalidatePreviews(); }, {signal});
  const currentTenant = route.params.get('tenant') || 'all';

  function render() {
    invalidatePreviews();
    if (!statusData) {
      root.innerHTML = loadingRows(4);
      return;
    }

    const {active_profile, profiles = [], stats = {}, tenants = [], table_sizes = {}} = statusData;
    const isReadOnly = active_profile?.mode === 'read_only';

    const profilesHTML = profiles.map(p => {
      const isCurrent = p.is_active;
      const test = testResults[p.id];
      const testStatusHTML = test
        ? test.ok
          ? `<span class="inline-status success">${icon('check')} Terhubung (${test.latency_ms} ms · ${esc(test.version || 'PostgreSQL')})</span>`
          : `<span class="inline-status error">${icon('close')} Gagal: ${esc(test.error || 'Timeout')}</span>`
        : '';

      const editURLHTML = p.id === 'remote'
        ? `<div class="field" style="margin-top:12px;"><label for="remote-url-input"><span>Alamat Target PC Intel</span><span class="meta">URI pengganti lengkap · kosong = tidak diubah</span></label><div class="split" style="gap:8px;"><input class="input mono" id="remote-url-input" type="password" autocomplete="new-password" value="" placeholder="Masukkan URI pengganti lengkap"><button class="button" data-action="save-remote-url" type="button">Simpan URI</button></div></div>`
        : '';

      return `
      <article class="database-card ${isCurrent ? 'is-active' : ''}">
        <div class="split">
          <div>
            <h3>${esc(p.name)}</h3>
            <p class="meta mono">${esc(p.masked_url)}</p>
          </div>
          <span class="badge ${isCurrent ? (p.mode === 'read_only' ? 'warning' : 'success') : 'neutral'}">
            <span class="status-dot"></span>${isCurrent ? 'Aktif' : p.mode === 'read_only' ? 'Read-Only' : 'Tersedia'}
          </span>
        </div>
        <p class="description">${esc(p.description || '')}</p>
        <div class="meta" style="margin: 8px 0;">Mode akses: <strong>${p.mode === 'read_only' ? 'Read-Only (Intel Cache & Inspeksi)' : 'Read-Write (Operasional Penuh)'}</strong></div>
        ${editURLHTML}
        <div class="card-actions" style="margin-top:16px; display:flex; gap:8px; align-items:center; flex-wrap:wrap;">
          <button class="button" data-action="test-profile" data-profile="${esc(p.id)}" type="button">${icon('refresh')} Tes Koneksi</button>
          <button class="button ${isCurrent ? '' : 'primary'}" data-action="switch-profile" data-profile="${esc(p.id)}" type="button"${isCurrent ? ' disabled' : ''}>
            ${isCurrent ? `${icon('check')} Sedang Digunakan` : 'Gunakan Database Ini'}
          </button>
          <div style="flex-basis:100%;">${testStatusHTML}</div>
        </div>
      </article>`;
    }).join('');

    const tenantsRows = (tenants || []).map(t => `
      <tr>
        <td><strong>${esc(t.tenant)}</strong></td>
        <td class="numeric num">${Number(t.count || 0).toLocaleString('id-ID')}</td>
        <td class="numeric num">${stats.alerts ? ((Number(t.count || 0) / stats.alerts) * 100).toFixed(1) + '%' : '—'}</td>
      </tr>
    `).join('');

    root.innerHTML = `
      <header class="page-header">
        <div>
          <h1 class="page-heading">Database &amp; Telemetri</h1>
          <p class="page-description">Kelola koneksi database (Laptop vs PC Intel), pantau kapasitas, dan kelola retensi telemetri.</p>
        </div>
        <div class="page-actions">
          <button class="button" data-action="refresh-status" type="button">${icon('refresh')} Perbarui Status</button>
        </div>
      </header>

      ${isReadOnly ? `<div class="notice" data-kind="warning"><p><strong>Mode Read-Only Aktif</strong>: Saat ini terhubung ke database <strong>${esc(active_profile.name)}</strong>. Operasi tulis (impor alert baru, pembuatan/penyuntingan kasus insiden, dan pembersihan data) dinonaktifkan untuk menjaga integritas data PC Intel.</p></div>` : ''}

      <section class="form-section">
        <h2 class="section-heading">Profil Database &amp; Sumber Data</h2>
        <p class="muted">Beralih antara PostgreSQL laptop lokal atau database PC lain di jaringan lokal secara langsung.</p>
        <div class="profile-grid" style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:16px; margin-top:16px;">
          ${profilesHTML}
        </div>
      </section>

      <section class="form-section" style="margin-top:24px;">
        <h2 class="section-heading">Ringkasan Kapasitas Telemetri</h2>
        <p class="muted">Statistik telemetri pada database yang sedang aktif (<strong>${esc(active_profile?.name || 'Lokal')}</strong>).</p>
        <div class="detail-grid" style="margin-top:16px;">
          <div class="key-value">
            <dt>Total Alert Wazuh</dt>
            <dd class="num" style="font-size:24px; font-weight:600;">${Number(stats.alerts || 0).toLocaleString('id-ID')}</dd>
            <dd class="meta">Ukuran tabel: ${esc(table_sizes['wazuh.alerts'] || '—')}</dd>
          </div>
          <div class="key-value">
            <dt>Kasus Insiden</dt>
            <dd class="num" style="font-size:24px; font-weight:600;">${Number(stats.groups || 0).toLocaleString('id-ID')}</dd>
            <dd class="meta">Ukuran tabel: ${esc(table_sizes['wazuh.analysis_groups'] || '—')}</dd>
          </div>
          <div class="key-value">
            <dt>Cache IP Intel (AbuseIPDB / Geo)</dt>
            <dd class="num" style="font-size:24px; font-weight:600;">${Number(stats.ip_intel_records || 0).toLocaleString('id-ID')}</dd>
            <dd class="meta">Entri reputasi IP terdaftar</dd>
          </div>
          <div class="key-value">
            <dt>Rentang Waktu Telemetri</dt>
            <dd style="font-size:15px; font-weight:500;">${esc(summarizeTelemetryRange(stats.earliest_telemetry, stats.latest_telemetry))}</dd>
            <dd class="meta">Berdasarkan timestamp bukti alert</dd>
          </div>
        </div>
      </section>

      ${tenants.length ? `
      <section class="form-section" style="margin-top:24px;">
        <h2 class="section-heading">Distribusi Tenant</h2>
        <div class="table-region" tabindex="0" style="margin-top:12px;">
          <table class="data-table">
            <thead>
              <tr>
                <th scope="col">Nama Tenant</th>
                <th scope="col" class="numeric">Jumlah Alert</th>
                <th scope="col" class="numeric">Porsi</th>
              </tr>
            </thead>
            <tbody>${tenantsRows}</tbody>
          </table>
        </div>
      </section>` : ''}

      <section class="form-section danger-zone" style="margin-top:32px; border:1px solid var(--border); padding:20px; border-radius:var(--radius-panel);">
        <h2 class="section-heading" style="color:var(--critical);">Pemeliharaan &amp; Retensi Data</h2>
        <p class="muted">Hapus data telemetri lawas untuk menghemat ruang disk atau hapus insiden yang sudah terselesaikan. Gunakan Pratinjau sebelum mengeksekusi.</p>

        <div style="display:grid; grid-template-columns:repeat(auto-fit, minmax(320px, 1fr)); gap:24px; margin-top:16px;">
          <form id="purge-alerts-form" class="stack">
            <h3>Pembersihan Alert Wazuh</h3>
            <label class="field">
              <span>Filter Waktu / Usia Data</span>
              <select class="select" id="purge-alerts-preset" name="preset">
                <option value="7">Lebih lama dari 7 hari</option>
                <option value="30" selected>Lebih lama dari 30 hari</option>
                <option value="60">Lebih lama dari 60 hari</option>
                <option value="90">Lebih lama dari 90 hari</option>
                <option value="custom">Rentang Waktu Kustom…</option>
              </select>
            </label>
            <div id="purge-custom-time-range" class="stack" style="display:none; gap:8px;">
              <label class="field"><span>Dari Tanggal &amp; Jam</span><input class="input" type="datetime-local" id="purge-from"></label>
              <label class="field"><span>Sampai Tanggal &amp; Jam</span><input class="input" type="datetime-local" id="purge-to"></label>
            </div>
            <label class="field">
              <span>Cakupan Tenant</span>
              <select class="select" id="purge-alerts-tenant" name="tenant">
                <option value="all">Semua tenant</option>
                ${(tenants || []).map(t => `<option value="${esc(t.tenant)}">Tenant ${esc(t.tenant)}</option>`).join('')}
              </select>
            </label>
            <div style="display:flex; gap:8px; margin-top:8px;">
              <button class="button" type="button" data-action="dry-run-alerts">Pratinjau Dampak</button>
              <button class="button danger" type="button" data-action="execute-purge-alerts"${isReadOnly ? ' disabled' : ''}>Hapus Alert</button>
            </div>
            <div id="purge-alerts-result" class="inline-status" style="margin-top:8px;" aria-live="polite"></div>
          </form>

          <form id="purge-incidents-form" class="stack">
            <h3>Pembersihan Kasus Insiden</h3>
            <p class="muted">GLOBAL — semua tenant; scope tenant workspace tidak membatasi operasi ini. Menghapus berkas kasus insiden beserta tautan buktinya (alert mentah tidak terhapus).</p>
            <label class="field">
              <span>Kriteria Kasus</span>
              <select class="select" id="purge-incidents-filter" name="status">
                <option value="closed_only" selected>Hanya kasus berstatus Ditutup / Diselesaikan (Closed &amp; Resolved)</option>
                <option value="all">Semua kasus insiden (Reset penuh kasus)</option>
              </select>
            </label>
            <div style="display:flex; gap:8px; margin-top:16px;">
              <button class="button" type="button" data-action="dry-run-incidents">Pratinjau Dampak</button>
              <button class="button danger" type="button" data-action="execute-purge-incidents"${isReadOnly ? ' disabled' : ''}>Hapus Insiden</button>
            </div>
            <div id="purge-incidents-result" class="inline-status" style="margin-top:8px;" aria-live="polite"></div>
          </form>
        </div>
      </section>
    `;

    const uriInput = root.querySelector('#remote-url-input');
    if (uriInput) uriInput.value = uriDraft;
    // Bind preset change
    root.querySelector('#purge-alerts-preset')?.addEventListener('change', e => {
      const customDiv = root.querySelector('#purge-custom-time-range');
      if (customDiv) customDiv.style.display = e.target.value === 'custom' ? 'grid' : 'none';
    });
  }

  async function loadStatus() {
    try {
      statusData = await json(apiURL('/api/database/status'), {signal});
      if (switchUnverified) {
        if (!databaseIdentity(statusData.active_profile)) throw new Error('Identitas database belum terverifikasi.');
        await ctx.databaseChanged?.(statusData);
        switchUnverified = false;
      }
      render();
      return true;
    } catch (err) {
      if (err.name !== 'AbortError') {
        root.innerHTML = errorState(`Gagal memuat status database: ${err.message}`);
        notify(`Gagal memuat status database: ${err.message}`, 'error');
      }
      return false;
    }
  }

  root.addEventListener('click', async e => {
    const btn = e.target.closest('button');
    if (!btn) return;

    const action = btn.dataset.action;

    if (action === 'refresh-status') {
      btn.disabled = true;
      if (await loadStatus()) notify('Status database diperbarui.', 'info');
      btn.disabled = false;
      return;
    }

    if (action === 'test-profile') {
      const pid = btn.dataset.profile;
      btn.disabled = true;
      btn.textContent = 'Menguji…';
      try {
        const res = await json(apiURL('/api/database/test'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({profile: pid}),
          signal,
        });
        testResults[pid] = res;
        render();
        notify(res.ok ? `Koneksi ${pid} sukses (${res.latency_ms} ms)` : `Koneksi gagal: ${res.error}`, res.ok ? 'success' : 'error');
      } catch (err) {
        if (err.name !== 'AbortError') notify(`Gagal tes koneksi: ${err.message}`, 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (action === 'switch-profile') {
      const pid = btn.dataset.profile;
      const expected = databaseIdentity(statusData?.profiles?.find(p => p.id === pid));
      if (!expected) { notify('Identitas target belum tersedia. Perbarui status terlebih dahulu.', 'error'); return; }
      if (uriDraft.trim() && !confirm('Ada URI yang belum disimpan. Buang perubahan dan beralih database?')) return;
      if (!confirm(`Beralih koneksi ke database "${pid}"? Data aktif workspace akan menyesuaikan database yang dipilih.`)) return;
      btn.disabled = true;
      try {
        invalidatePreviews();
        switchUnverified = true;
        await ctx.databaseChanged?.(null);
        await json(apiURL('/api/database/switch'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({profile: pid}),
          signal,
        });
        uriDraft = '';
        const verified = await json(apiURL('/api/database/status'), {signal});
        if (databaseIdentity(verified.active_profile) !== expected) throw new Error('Target database tidak cocok dengan readback. Status pergantian belum terverifikasi.');
        statusData = verified;
        await ctx.databaseChanged?.(verified);
        switchUnverified = false;
        render();
        notify(`Berhasil beralih ke database ${pid}.`, 'success');
      } catch (err) {
        statusData = null;
        if (err.name !== 'AbortError') {
          root.innerHTML = `${errorState('Pergantian database belum terverifikasi. Perbarui status untuk memeriksa database aktif.')}<button class="button" data-action="refresh-status" type="button">Perbarui Status</button>`;
          notify(`Gagal beralih database: ${err.message}`, 'error');
        }
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (action === 'save-remote-url') {
      const input = root.querySelector('#remote-url-input');
      const val = String(input?.value || '').trim();
      if (!val) { notify('URI tidak boleh kosong.', 'error'); return; }
      btn.disabled = true;
      try {
        await json(apiURL('/api/database/config'), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({profile: 'remote', url: val}),
          signal,
        });
        uriDraft = '';
        notify('URI Remote PC Intel disimpan.', 'success');
        await loadStatus();
      } catch (err) {
        if (err.name !== 'AbortError') notify(err.message, 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }

    if (action === 'dry-run-alerts' || action === 'execute-purge-alerts') {
      const isDry = action === 'dry-run-alerts';
      const preset = root.querySelector('#purge-alerts-preset')?.value;
      const tenant = root.querySelector('#purge-alerts-tenant')?.value || 'all';
      const resultSlot = root.querySelector('#purge-alerts-result');

      let older_than_days = null, time_from = '', time_to = '';
      if (preset === 'custom') {
        time_from = root.querySelector('#purge-from')?.value || '';
        time_to = root.querySelector('#purge-to')?.value || '';
        if (!time_from && !time_to) {
          notify('Pilih rentang tanggal untuk filter kustom.', 'error');
          return;
        }
      } else {
        older_than_days = Number(preset) || 30;
      }

      await maintain('alerts', {older_than_days, time_from, time_to, tenant}, isDry, btn, resultSlot);
      return;
    }

    if (action === 'dry-run-incidents' || action === 'execute-purge-incidents') {
      const isDry = action === 'dry-run-incidents';
      const status = root.querySelector('#purge-incidents-filter')?.value || 'closed_only';
      const resultSlot = root.querySelector('#purge-incidents-result');

      await maintain('incidents', {status}, isDry, btn, resultSlot);
      return;
    }
  }, {signal});

  async function maintain(kind, filters, dry, btn, slot) {
    const key = JSON.stringify(filters), identity = databaseIdentity(statusData?.active_profile);
    const preview = previews[kind], version = previewVersion;
    btn.disabled = true;
    try {
      if (!identity) throw new Error('Identitas database belum terverifikasi. Perbarui status.');
      if (!dry && (!preview || preview.key !== key || preview.identity !== identity || Date.now() - preview.at > 60000)) throw new Error('Pratinjau baru diperlukan untuk database dan filter yang sama (berlaku 60 detik).');
      const current = await json(apiURL('/api/database/status'), {signal});
      if (databaseIdentity(current.active_profile) !== identity) throw new Error('Database berubah. Perbarui status dan buat pratinjau baru.');
      if (!dry && current.active_profile.mode !== 'read_write') throw new Error('Database Read-Only: pembersihan dinonaktifkan.');
      const payload = dry ? {...filters} : {...preview.payload};
      if (!dry && preview.preview_token) payload.preview_token = preview.preview_token;
      if (dry && kind === 'alerts') {
        // Freeze relative age so preview and execution use exactly the same cutoff.
        payload.time_from = filters.time_from ? new Date(filters.time_from).toISOString() : '';
        payload.time_to = filters.time_to ? new Date(filters.time_to).toISOString() : filters.older_than_days ? new Date(Date.now() - filters.older_than_days * 86400000).toISOString() : '';
        payload.older_than_days = null;
      }
      if (version !== previewVersion) throw new Error('Filter berubah selama permintaan. Buat pratinjau baru.');
      if (!dry && !confirm(`Hapus permanen dari database ${current.active_profile.id} (${current.active_profile.masked_url})? Pratinjau: ${preview.count} ${kind}. Filter: ${JSON.stringify(payload)}. ${kind === 'incidents' ? 'GLOBAL: semua tenant; scope workspace diabaikan. Alert mentah tidak dihapus.' : `Tenant: ${filters.tenant}.`} Jumlah dapat berubah setelah pratinjau.`)) return;
      if (!dry && (previews[kind] !== preview || Date.now() - preview.at > 60000)) throw new Error('Pratinjau kedaluwarsa atau sudah digunakan. Buat pratinjau baru.');
      delete previews[kind];
      const res = await json(apiURL(`/api/database/purge-${kind}`), {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...payload, dry_run:dry}), signal});
      if (dry) {
        const after = await json(apiURL('/api/database/status'), {signal});
        if (databaseIdentity(after.active_profile) !== identity || version !== previewVersion || res.dry_run !== true || !Number.isSafeInteger(res.count) || res.count < 0) throw new Error('Pratinjau tidak valid atau database/filter berubah. Ulangi pratinjau.');
        previews[kind] = {key, identity, payload, count:res.count, at:Date.now(), preview_token: res.preview_token};
        if (slot) slot.textContent = `Pratinjau: ${res.count} ${kind}; database ${current.active_profile.id}; ${kind === 'incidents' ? 'GLOBAL — semua tenant (scope workspace diabaikan)' : `tenant ${filters.tenant}`}; filter ${JSON.stringify(payload)}. Berlaku 60 detik; bukan snapshot atomik.`;
      } else {
        if (res.dry_run !== false || !Number.isSafeInteger(res.deleted) || res.deleted < 0) throw new Error('Hasil penghapusan belum terverifikasi. Jangan ulangi tanpa pratinjau baru.');
        const after = await json(apiURL('/api/database/status'), {signal});
        if (databaseIdentity(after.active_profile) !== identity) throw new Error('Database berubah setelah penghapusan. Hasil belum terverifikasi; jangan ulangi tanpa pratinjau baru.');
        statusData = after;render();
        notify(`${res.deleted} ${kind} dihapus menurut respons server.`, 'success');
      }
    } catch (err) {
      delete previews[kind];
      if (err.name !== 'AbortError') { if (slot) slot.textContent = err.message; notify(err.message, 'error'); }
    } finally { btn.disabled = false; }
  }

  await loadStatus();
  return () => {};
}
