import {json, apiURL, copyText} from '../../api/client.js';
import {emptyState, errorState, loadingRows, defangText, esc, icon} from '../../ui/primitives.js';
import {tenantValues} from '../../state/scope.js';
import {withParams} from '../../router.js';
import {createStatsSession} from '../../state/stats.js';
import {drilldownScrollBehavior, normalizeStatsQuery, statsScopeParams, generateStatsCSV, generateMarkdownSummary, isMaliciousPath, isMaliciousAlert} from './model.js';
import {statsPage, statsResults, renderAppliedFilters} from './render.js';

export function mount(ctx) {
  const {root, route, signal, navigate, notify} = ctx;
  const query = normalizeStatsQuery(route.params);
  const session = createStatsSession();

  let activeRequest = null;
  let currentData = null;
  let drilldownAlerts = null;
  const selectedIds = new Set();
  const selectedSecondaryKeys = new Set();
  let activeSpotterMode = 'all';
  const expandedLogIds = new Set();
  let showAllLogs = false;
  let showAllSecondary = false;

  root.classList.add('stats-page');
  root.innerHTML = statsPage(query);
  const resultsContainer = root.querySelector('#stats-results');
  const batchDialog = root.querySelector('#stats-batch-incident-dialog');
  const batchForm = root.querySelector('#stats-batch-incident-form');

  const on = (el, type, fn) => el?.addEventListener(type, fn, {signal});

  function updateRoute(changes, {replace = false} = {}) {
    const p = statsScopeParams(query);
    for (const [k, v] of Object.entries(changes)) {
      if (v === null || v === undefined || v === '') p.delete(k);
      else p.set(k, String(v));
    }
    navigate(withParams('/stats', p), {replace});
  }

  function renderView() {
    const appliedContainer = root.querySelector('#stats-applied-filters');
    if (appliedContainer) {
      appliedContainer.innerHTML = renderAppliedFilters(query, currentData);
      appliedContainer.style.display = ((query.facet && query.facet_value) || (query.secondary_facet && query.secondary_facet_value)) ? 'flex' : 'none';
    }

    if (!currentData || currentData.total === 0) {
      resultsContainer.innerHTML = emptyState(
        'Tidak ada data statistik pada scope ini',
        'Coba ubah filter rentang waktu atau pilih acuan pivot lain.',
        `<button class="button primary" type="button" data-action="reset-stats">Reset Filter</button>`
      );
      return;
    }
    resultsContainer.innerHTML = statsResults(currentData, query, {
      drilldownAlerts,
      selectedIds: [...selectedIds],
      expandedLogIds,
      showAllLogs,
      selectedSecondaryKeys: [...selectedSecondaryKeys],
      showAllSecondary,
    });
  }

  async function loadData() {
    activeRequest?.abort();
    activeRequest = new AbortController();
    const version = session.nextRequest();

    resultsContainer.innerHTML = loadingRows(4);

    try {
      const fetchParams = statsScopeParams(query);
      const data = await json(apiURL('/api/stats', fetchParams), {signal: activeRequest.signal});
      if (signal?.aborted || !session.isCurrent(version)) return;
      // If drilldown facet is active, fetch sample alerts for interactive evidence table.
      // Failures must reach the error handler, never masquerade as empty evidence.
      if (query.facet && query.facet_value) {
        const sampleParams = statsScopeParams(query);
        sampleParams.set('limit', '50');
        sampleParams.set('summary', 'false');
        const sampleData = await json(apiURL('/api/alerts', sampleParams), {signal: activeRequest.signal});
        if (signal?.aborted || !session.isCurrent(version)) return;
        drilldownAlerts = sampleData.items || [];
      } else {
        drilldownAlerts = null;
        selectedIds.clear();
        expandedLogIds.clear();
      }

      currentData = data;
      showAllSecondary = false;
      renderView();
      if (query.secondary_facet && query.secondary_facet_value) {
        setTimeout(() => {
          const evidenceEl = root.querySelector('.drilldown-evidence-section');
          if (!signal?.aborted) evidenceEl?.scrollIntoView({behavior: drilldownScrollBehavior(), block: 'nearest'});
        }, 50);
      }
    } catch (err) {
      if (err.name !== 'AbortError' && !signal?.aborted && session.isCurrent(version)) {
        let msg = err.message || 'Gagal memuat data statistik.';
        if (msg === 'Not Found' || err.status === 404) {
          msg = 'Endpoint statistik tidak ditemukan di server backend (404 Not Found). Jika menjalankan via Docker, pastikan container sudah dimuat ulang (docker compose restart arbiter).';
        }
        resultsContainer.innerHTML = errorState(msg);
      }
    }
  }

  async function resolveAlertIdsForSecondaryKeys(keys = [], spotterMode = 'all') {
    if (!keys.length) return [];
    try {
      const res = await json('/api/stats/facet-alert-ids', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          tenant: tenantValues(query),
          q: query.q,
          status: query.status,
          filter_preset: query.filter_preset,
          review_status: query.review_status,
          time_preset: query.time_preset,
          time_from: query.time_from,
          time_to: query.time_to,
          facet: query.facet,
          facet_value: query.facet_value,
          secondary_facet: query.secondary_pivot,
          secondary_facet_values: keys,
          spotter_mode: spotterMode,
        }),
        signal,
      });
      return res.alert_pks || [];
    } catch (err) {
      if (err.name !== 'AbortError') notify(`Gagal mengambil alert: ${err.message}`, 'error');
      return [];
    }
  }

  async function loadBatchIncidentOptions() {
    const selectEl = root.querySelector('#stats-batch-incident-select');
    const hintEl = root.querySelector('#stats-batch-incident-hint');
    if (!selectEl) return;

    selectEl.innerHTML = '<option value="">Memuat daftar insiden…</option>';
    if (hintEl) hintEl.innerHTML = '';

    try {
      const activeTenants = tenantValues(query);
      const groups = await json(apiURL('/api/groups', {tenant: activeTenants}), {signal});
      if (!groups.length) {
        selectEl.innerHTML = '<option value="">Belum ada kasus insiden pada scope ini</option>';
        if (hintEl) {
          const params = new URLSearchParams({alert_ids: [...selectedIds].join(',')});
          for (const tenant of activeTenants) params.append('tenant', tenant);
          hintEl.innerHTML = `Belum ada insiden aktif. <a href="${esc(withParams('/incidents/new', params))}" class="text-button" style="text-decoration:underline;">Buat kasus insiden baru sekarang &rarr;</a>`;
        }
      } else {
        selectEl.innerHTML = '<option value="">Pilih insiden sasaran…</option>' +
          groups.map(g => `<option value="${esc(g.id)}">${esc(g.title)} (${g.alert_count ?? 0} bukti)</option>`).join('');
      }
    } catch (err) {
      if (err.name !== 'AbortError') {
        selectEl.innerHTML = `<option value="">Gagal memuat insiden (${esc(err.message || 'Koneksi error')})</option>`;
        if (hintEl) {
          hintEl.innerHTML = `<span style="color:var(--danger, #ff8b8b);">Gagal terhubung ke server. Pastikan layanan aktif lalu klik 'Muat ulang'.</span>`;
        }
      }
    }
  }

  function downloadFile(content, filename, type) {
    const blob = new Blob([content], {type});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // Event handlers
  on(root, 'change', e => {
    if (e.target.id === 'stats-pivot') {
      const val = e.target.value;
      const wrap = root.querySelector('#stats-pattern-wrap');
      if (wrap) wrap.style.display = val === 'pattern' ? 'block' : 'none';
      updateRoute({pivot_by: val, facet: null, facet_value: null});
    }
    if (e.target.id === 'stats-secondary-pivot') {
      updateRoute({secondary_pivot: e.target.value || null});
    }
    if (e.target.id === 'stats-top-n') {
      updateRoute({top_n: Number(e.target.value)});
    }
    if (e.target.id === 'stats-time') {
      const val = e.target.value;
      const customWrap = root.querySelector('#stats-custom-time-wrap');
      if (customWrap) customWrap.style.display = val === 'custom' ? 'grid' : 'none';
      updateRoute({time_preset: val, time_from: null, time_to: null});
    }
    if (e.target.id === 'stats-time-from' || e.target.id === 'stats-time-to') {
      const tf = root.querySelector('#stats-time-from')?.value || '';
      const tt = root.querySelector('#stats-time-to')?.value || '';
      updateRoute({time_preset: 'custom', time_from: tf, time_to: tt});
    }
    if (e.target.id === 'stats-preset-select') {
      const preset = e.target.value;
      if (preset === 'preset-top-rules-24h') {
        updateRoute({pivot_by: 'rule_description', time_preset: '24h', metric: 'alerts'});
      } else if (preset === 'preset-top-ips-7d') {
        updateRoute({pivot_by: 'source_ip', time_preset: '7d', metric: 'alerts'});
      } else if (preset === 'preset-http-status') {
        updateRoute({pivot_by: 'http_status', metric: 'events'});
      }
    }
    if (e.target.id === 'stats-select-all-drilldown') {
      if (e.target.checked && drilldownAlerts) {
        drilldownAlerts.forEach(a => selectedIds.add(a.id));
      } else {
        selectedIds.clear();
      }
      renderView();
    }
    if (e.target.matches('[data-select-drilldown]')) {
      const aid = Number(e.target.dataset.selectDrilldown);
      if (e.target.checked) selectedIds.add(aid);
      else selectedIds.delete(aid);
      renderView();
    }
    if (e.target.id === 'stats-select-all-secondary') {
      if (e.target.checked && currentData?.secondary_breakdown) {
        currentData.secondary_breakdown.forEach(sb => selectedSecondaryKeys.add(sb.key));
      } else {
        selectedSecondaryKeys.clear();
      }
      renderView();
    }
    if (e.target.matches('[data-select-secondary-key]')) {
      const sk = e.target.dataset.selectSecondaryKey;
      if (e.target.checked) selectedSecondaryKeys.add(sk);
      else selectedSecondaryKeys.delete(sk);
      renderView();
    }
  });

  on(root, 'click', async e => {
    const seg = e.target.closest('[data-secondary-key]');
    if (seg) {
      const priKey = seg.dataset.primaryKey;
      const secKey = seg.dataset.secondaryKey;
      if (priKey && secKey && query.secondary_pivot) {
        updateRoute({
          facet: query.pivot_by,
          facet_value: priKey,
          secondary_facet: query.secondary_pivot,
          secondary_facet_value: secKey,
        });
        return;
      }
    }

    const btn = e.target.closest('button, [role="button"]');
    if (!btn) return;

    if (btn.dataset.metric) {
      updateRoute({metric: btn.dataset.metric});
      return;
    }
    if (btn.dataset.chart) {
      updateRoute({chart: btn.dataset.chart});
      return;
    }
    if (btn.id === 'btn-apply-pattern') {
      const input = root.querySelector('#stats-pattern-input');
      const val = input?.value?.trim() || '';
      if (!val) {
        notify('Ketik kata kunci untuk pencarian pola teks.', 'error');
        return;
      }
      updateRoute({pattern: val});
      return;
    }
    if (btn.id === 'btn-save-preset') {
      const name = prompt('Beri nama untuk preset statistik ini:');
      if (name && name.trim()) {
        try {
          const key = `arbiter:stats-presets:${query.tenantScope.key}`;
          const existing = JSON.parse(localStorage.getItem(key) || '{}');
          existing[name.trim()] = {
            pivot_by: query.pivot_by,
            metric: query.metric,
            chart: query.chart,
            top_n: query.top_n,
            time_preset: query.time_preset,
          };
          localStorage.setItem(key, JSON.stringify(existing));
          notify(`Preset "${name.trim()}" berhasil disimpan.`, 'success');
        } catch {
          notify('Gagal menyimpan preset ke penyimpanan lokal browser.', 'error');
        }
      }
      return;
    }
    if (btn.id === 'btn-clear-drilldown') {
      updateRoute({facet: null, facet_value: null, secondary_facet: null, secondary_facet_value: null});
      return;
    }
    if (btn.id === 'btn-clear-secondary-drilldown') {
      updateRoute({secondary_facet: null, secondary_facet_value: null});
      return;
    }
    if (btn.dataset.secondaryDrillKey || btn.dataset.secondaryLegendKey) {
      const secKey = btn.dataset.secondaryDrillKey || btn.dataset.secondaryLegendKey;
      if (secKey && query.secondary_pivot) {
        updateRoute({secondary_facet: query.secondary_pivot, secondary_facet_value: secKey});
      }
      return;
    }
    if (btn.dataset.drillKey || btn.dataset.chartKey) {
      const key = btn.dataset.drillKey || btn.dataset.chartKey;
      if (key && key !== 'Lainnya') {
        updateRoute({facet: query.pivot_by, facet_value: key, secondary_facet: null, secondary_facet_value: null});
      }
      return;
    }
    if (btn.dataset.action === 'reset-stats') {
      const p = new URLSearchParams();
      for (const t of query.tenants) p.append('tenant', t);
      navigate(withParams('/stats', p));
      return;
    }
    if (btn.dataset.action === 'export-csv') {
      if (!currentData) return;
      const csv = generateStatsCSV(currentData);
      downloadFile(csv, `arbiter-stats-${query.pivot_by}.csv`, 'text/csv;charset=utf-8');
      notify('File CSV statistik berhasil diunduh.', 'success');
      return;
    }
    if (btn.dataset.action === 'export-svg') {
      const svg = root.querySelector('.chart-svg');
      if (!svg) {
        notify('Grafik tidak tersedia untuk diunduh.', 'error');
        return;
      }
      const svgText = new XMLSerializer().serializeToString(svg);
      downloadFile(svgText, `arbiter-chart-${query.pivot_by}.svg`, 'image/svg+xml');
      notify('Grafik SVG berhasil diunduh.', 'success');
      return;
    }
    if (btn.dataset.action === 'copy-summary') {
      if (!currentData) return;
      const md = generateMarkdownSummary(currentData);
      try {
        await copyText(md);
        notify('Ringkasan statistik disalin ke clipboard.', 'success');
      } catch {
        notify('Gagal menyalin ringkasan. Izin clipboard tidak diberikan.', 'error');
      }
      return;
    }
    if (btn.dataset.action === 'retry') {
      await loadData();
      return;
    }
    if (btn.id === 'btn-malicious-spotter') {
      const breakdown = currentData?.secondary_breakdown || [];
      if (!breakdown.length) {
        notify('Belum ada rincian sub-kategori untuk diperiksa.', 'info');
        return;
      }
      const matched = breakdown.filter(sb => isMaliciousPath(sb.key));
      if (!matched.length) {
        notify('Tidak ditemukan sub-kategori dengan pola mencurigakan.', 'info');
        return;
      }
      selectedSecondaryKeys.clear();
      matched.forEach(sb => selectedSecondaryKeys.add(sb.key));
      activeSpotterMode = 'malicious';
      const primaryCategoryTotal = breakdown.reduce((acc, sb) => acc + (sb.count || 0), 0) || currentData?.total || 1;
      const totalAlerts = matched.reduce((acc, sb) => acc + (sb.count || 0), 0);
      const pct = Math.round((totalAlerts / primaryCategoryTotal) * 1000) / 10;
      notify(`Malicious Spotter: ${matched.length} sub-kategori mencurigakan terpilih (${totalAlerts.toLocaleString('id-ID')} alert · ${pct}%).`, 'success');
      renderView();
      return;
    }
    if (btn.id === 'btn-benign-spotter') {
      const breakdown = currentData?.secondary_breakdown || [];
      if (!breakdown.length) {
        notify('Belum ada rincian sub-kategori untuk diperiksa.', 'info');
        return;
      }
      const matched = breakdown.filter(sb => !isMaliciousPath(sb.key));
      if (!matched.length) {
        notify('Tidak ditemukan sub-kategori non-mencurigakan.', 'info');
        return;
      }
      selectedSecondaryKeys.clear();
      matched.forEach(sb => selectedSecondaryKeys.add(sb.key));
      activeSpotterMode = 'benign';
      const primaryCategoryTotal = breakdown.reduce((acc, sb) => acc + (sb.count || 0), 0) || currentData?.total || 1;
      const totalAlerts = matched.reduce((acc, sb) => acc + (sb.count || 0), 0);
      const pct = Math.round((totalAlerts / primaryCategoryTotal) * 1000) / 10;
      notify(`Benign Spotter: ${matched.length} sub-kategori non-mencurigakan terpilih (${totalAlerts.toLocaleString('id-ID')} alert · ${pct}%).`, 'success');
      renderView();
      return;
    }
    if (btn.id === 'btn-evidence-malicious-spotter') {
      if (!drilldownAlerts?.length) return;
      const matched = drilldownAlerts.filter(a => isMaliciousAlert(a));
      if (!matched.length) {
        notify('Tidak ada alert mencurigakan di antara bukti yang tampil.', 'info');
        return;
      }
      selectedIds.clear();
      matched.forEach(a => selectedIds.add(a.id));
      const pct = Math.round((matched.length / drilldownAlerts.length) * 1000) / 10;
      notify(`Malicious Spotter: ${matched.length} alert individual mencurigakan terpilih (${pct}% dari bukti tampil).`, 'success');
      renderView();
      return;
    }
    if (btn.id === 'btn-evidence-benign-spotter') {
      if (!drilldownAlerts?.length) return;
      const matched = drilldownAlerts.filter(a => !isMaliciousAlert(a));
      if (!matched.length) {
        notify('Tidak ada alert non-mencurigakan di antara bukti yang tampil.', 'info');
        return;
      }
      selectedIds.clear();
      matched.forEach(a => selectedIds.add(a.id));
      const pct = Math.round((matched.length / drilldownAlerts.length) * 1000) / 10;
      notify(`Benign Spotter: ${matched.length} alert individual non-mencurigakan terpilih (${pct}% dari bukti tampil).`, 'success');
      renderView();
      return;
    }
    if (btn.dataset.action === 'clear-secondary-selection') {
      selectedSecondaryKeys.clear();
      activeSpotterMode = 'all';
      renderView();
      return;
    }
    if (btn.dataset.action === 'add-secondary-to-incident') {
      const key = btn.dataset.secondaryKey;
      if (!key) return;
      btn.disabled = true;
      notify(`Mengambil alert untuk sub-kategori "${key}"…`, 'info');
      try {
        const pks = await resolveAlertIdsForSecondaryKeys([key], 'all');
        if (!pks.length) {
          notify('Tidak ada alert yang ditemukan untuk kategori ini.', 'error');
          return;
        }
        pks.forEach(pk => selectedIds.add(pk));
        const countEl = root.querySelector('#stats-batch-incident-count');
        if (countEl) countEl.textContent = String(selectedIds.size);
        batchDialog?.showModal();
        await loadBatchIncidentOptions();
        renderView();
      } finally {
        btn.disabled = false;
      }
      return;
    }
    if (btn.dataset.action === 'batch-secondary-add-incident') {
      const keys = [...selectedSecondaryKeys];
      if (!keys.length) {
        notify('Pilih minimal satu sub-kategori terlebih dahulu.', 'error');
        return;
      }
      btn.disabled = true;
      notify(`Mengambil alert untuk ${keys.length} sub-kategori terpilih (${activeSpotterMode})…`, 'info');
      try {
        const pks = await resolveAlertIdsForSecondaryKeys(keys, activeSpotterMode);
        if (!pks.length) {
          notify('Tidak ada alert yang sesuai dengan filter spotter untuk kategori terpilih.', 'error');
          return;
        }
        pks.forEach(pk => selectedIds.add(pk));
        const countEl = root.querySelector('#stats-batch-incident-count');
        if (countEl) countEl.textContent = String(selectedIds.size);
        batchDialog?.showModal();
        await loadBatchIncidentOptions();
        renderView();
      } finally {
        btn.disabled = false;
      }
      return;
    }
    if (btn.dataset.action === 'batch-secondary-create-incident') {
      const keys = [...selectedSecondaryKeys];
      if (!keys.length) {
        notify('Pilih minimal satu sub-kategori terlebih dahulu.', 'error');
        return;
      }
      btn.disabled = true;
      try {
        const pks = await resolveAlertIdsForSecondaryKeys(keys, activeSpotterMode);
        if (!pks.length) {
          notify('Tidak ada alert yang sesuai dengan filter spotter untuk kategori terpilih.', 'error');
          return;
        }
        const p = new URLSearchParams({alert_ids: pks.join(',')});
        for (const tenant of tenantValues(query)) p.append('tenant', tenant);
        navigate(withParams('/incidents/new', p));
      } finally {
        btn.disabled = false;
      }
      return;
    }
    if (btn.dataset.action === 'batch-secondary-review') {
      const keys = [...selectedSecondaryKeys];
      if (!keys.length) return;
      btn.disabled = true;
      try {
        const pks = await resolveAlertIdsForSecondaryKeys(keys, activeSpotterMode);
        if (pks.length) {
          await json(apiURL('/api/alerts/batch-review', {tenant: query.tenant}), {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({alert_ids: pks, is_reviewed: true, tenant: query.tenant}),
            signal,
          });
          notify(`${pks.length} alert dari ${keys.length} sub-kategori ditandai direview.`, 'success');
          await loadData();
        }
      } catch (err) {
        if (err.name !== 'AbortError') notify(err.message, 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }

    // Interactive drill-down actions
    if (btn.id === 'btn-toggle-all-secondary' || btn.dataset.statsAction === 'toggle-all-secondary') {
      showAllSecondary = !showAllSecondary;
      renderView();
      return;
    }
    if (btn.id === 'btn-toggle-all-stats-logs') {
      showAllLogs = !showAllLogs;
      renderView();
      return;
    }
    if (btn.dataset.statsAction === 'toggle-log') {
      const aid = Number(btn.dataset.alertId);
      if (expandedLogIds.has(aid)) expandedLogIds.delete(aid);
      else expandedLogIds.add(aid);
      renderView();
      return;
    }
    if (btn.dataset.statsAction === 'clear-selection') {
      selectedIds.clear();
      renderView();
      return;
    }
    if (btn.dataset.statsAction === 'create-incident') {
      const ids = [...selectedIds];
      if (!ids.length) {
        notify('Pilih minimal satu alert terlebih dahulu.', 'error');
        return;
      }
      const p = new URLSearchParams({alert_ids: ids.join(',')});
      for (const tenant of tenantValues(query)) p.append('tenant', tenant);
      navigate(withParams('/incidents/new', p));
      return;
    }
    if (btn.id === 'btn-reload-batch-incidents') {
      await loadBatchIncidentOptions();
      return;
    }
    if (btn.dataset.statsAction === 'add-to-incident') {
      const ids = [...selectedIds];
      if (!ids.length) {
        notify('Pilih minimal satu alert terlebih dahulu.', 'error');
        return;
      }
      const countEl = root.querySelector('#stats-batch-incident-count');
      if (countEl) countEl.textContent = String(ids.length);
      batchDialog?.showModal();
      await loadBatchIncidentOptions();
      return;
    }
    if (btn.hasAttribute('data-close-stats-batch-incident')) {
      batchDialog?.close();
      return;
    }
    if (btn.dataset.statsAction === 'batch-review' || btn.dataset.statsAction === 'batch-unreview') {
      const ids = [...selectedIds];
      if (!ids.length) return;
      const isRev = btn.dataset.statsAction === 'batch-review';
      btn.disabled = true;
      try {
        await json(apiURL('/api/alerts/batch-review', {tenant: query.tenant}), {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({alert_ids: ids, is_reviewed: isRev, tenant: query.tenant}),
          signal,
        });
        notify(isRev ? `${ids.length} alert ditandai direview.` : `${ids.length} alert ditandai belum direview.`, 'success');
        await loadData();
      } catch (err) {
        if (err.name !== 'AbortError') notify(err.message, 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }
    if (btn.dataset.statsAction === 'copy-logs' || btn.dataset.statsAction === 'copy-redacted') {
      const ids = [...selectedIds];
      if (!ids.length) return;
      const isRedacted = btn.dataset.statsAction === 'copy-redacted';
      btn.disabled = true;
      try {
        const matchingAlerts = (drilldownAlerts || []).filter(a => selectedIds.has(a.id));
        matchingAlerts.sort((a, b) => {
          const rA = String(a.rule_id || '');
          const rB = String(b.rule_id || '');
          if (rA !== rB) return rA.localeCompare(rB);
          return String(a.timestamp || '').localeCompare(String(b.timestamp || ''));
        });
        let fullText = matchingAlerts.map(a => {
          const raw = a.full_log || a.raw?.full_log || (a.raw ? JSON.stringify(a.raw, null, 2) : 'Log tidak tersedia.');
          return `Alert #${a.alert_id || a.id} (${a.description || 'Alert'})\n${raw}`;
        }).join('\n\n---\n\n');
        if (isRedacted) {
          const res = await json('/api/sanitize-logs', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text: fullText}),
            signal,
          });
          fullText = res.sanitized;
        }
        await copyText(fullText);
        notify(`${ids.length} log alert berhasil disalin.`, 'success');
      } catch (err) {
        if (err.name !== 'AbortError') notify(err.message, 'error');
      } finally {
        btn.disabled = false;
      }
      return;
    }
    if (btn.dataset.statsAction === 'copy-single-log') {
      const aid = Number(btn.dataset.alertId);
      const item = (drilldownAlerts || []).find(a => a.id === aid);
      const text = item?.full_log || item?.raw?.full_log || (item?.raw ? JSON.stringify(item.raw, null, 2) : '');
      if (text) {
        await copyText(text);
        notify('Log alert disalin.', 'info');
      }
      return;
    }
    if (btn.dataset.statsAction === 'copy-single-redacted') {
      const aid = Number(btn.dataset.alertId);
      const item = (drilldownAlerts || []).find(a => a.id === aid);
      let text = item?.full_log || item?.raw?.full_log || (item?.raw ? JSON.stringify(item.raw, null, 2) : '');
      if (text) {
        try {
          const res = await json('/api/sanitize-logs', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({text}),
            signal,
          });
          await copyText(res.sanitized);
          notify('Versi tersamarkan disalin.', 'info');
        } catch {
          notify('Gagal menyamarkan log.', 'error');
        }
      }
      return;
    }
    if (btn.dataset.statsAction === 'copy-single-defanged') {
      const aid = Number(btn.dataset.alertId);
      const item = (drilldownAlerts || []).find(a => a.id === aid);
      const text = item?.full_log || item?.raw?.full_log || '';
      if (text) {
        await copyText(defangText(text));
        notify('Versi defanged disalin.', 'info');
      }
      return;
    }
  });

  on(batchForm, 'submit', async e => {
    e.preventDefault();
    const form = new FormData(batchForm);
    const groupId = form.get('group_id');
    const ids = [...selectedIds];
    if (!groupId) {
      notify('Pilih insiden terlebih dahulu.', 'error');
      return;
    }
    if (!ids.length) {
      batchDialog?.close();
      notify('Tidak ada alert yang dipilih.', 'error');
      return;
    }
    const submitBtn = batchForm.querySelector('button[type="submit"]');
    if (submitBtn) submitBtn.disabled = true;
    try {
      const activeTenants = tenantValues(query);
      await json(apiURL(`/api/groups/${encodeURIComponent(groupId)}/members`, {tenant: activeTenants}), {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({alert_pks: ids, tenant: query.tenant}),
        signal,
      });
      batchDialog?.close();
      selectedIds.clear();
      notify(`${ids.length} alert berhasil ditautkan ke kasus insiden.`, 'success');
      await loadData();
    } catch (err) {
      if (err.name !== 'AbortError') notify(err.message, 'error');
    } finally {
      if (submitBtn) submitBtn.disabled = false;
    }
  });

  on(root, 'keydown', e => {
    if (e.target.id === 'stats-pattern-input' && e.key === 'Enter') {
      e.preventDefault();
      const val = e.target.value?.trim() || '';
      if (val) updateRoute({pattern: val});
    }
    if ((e.key === 'Enter' || e.key === ' ') && e.target.matches('[data-secondary-key]') && query.secondary_pivot) {
      e.preventDefault();
      updateRoute({facet: query.pivot_by, facet_value: e.target.dataset.primaryKey, secondary_facet: query.secondary_pivot, secondary_facet_value: e.target.dataset.secondaryKey});
      return;
    }
    if ((e.key === 'Enter' || e.key === ' ') && (e.target.matches('[data-chart-key]') || e.target.matches('[data-drill-key]'))) {
      e.preventDefault();
      const key = e.target.dataset.chartKey || e.target.dataset.drillKey;
      if (key && key !== 'Lainnya') {
        updateRoute({facet: query.pivot_by, facet_value: key});
      }
    }
    if (e.key === 'Escape' && batchDialog?.open) {
      batchDialog.close();
    }
  });

  loadData();

  return () => {
    root.classList.remove('stats-page');
    session.dispose();
    activeRequest?.abort();
    batchDialog?.close();
  };
}
