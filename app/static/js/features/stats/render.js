import {esc, icon, severity} from '../../ui/primitives.js';
import {PIVOT_OPTIONS, METRIC_OPTIONS, CHART_OPTIONS, distributionPercentages, triageRouteFromStats, isMaliciousPath, isMaliciousAlert} from './model.js';
import {renderBarChart, renderDonutChart, renderLineChart} from '../../ui/charts.js';

export function renderAppliedFilters(query, data = null) {
  if (!((query.facet && query.facet_value) || (query.secondary_facet && query.secondary_facet_value))) {
    return '';
  }
  const metricLabel = data?.metric === 'events' ? 'event' : 'alert';
  const parentTotal = data?.parent_total;
  const primPct = data?.primary_percentage_of_total;
  const secPct = data?.secondary_percentage_of_parent;
  const totPct = data?.secondary_percentage_of_total;
  const filteredCount = data?.total;

  return `
    ${query.facet && query.facet_value ? `
      <span class="badge neutral">
        Pivot Utama: <strong>${esc(query.facet)} = ${esc(query.facet_value)}</strong>
        ${primPct !== undefined && primPct !== null ? `
          <span class="font-medium filter-pct">
            ${(parentTotal || filteredCount || 0).toLocaleString('id-ID')} ${metricLabel} · ${primPct}% dari workspace
          </span>
        ` : (parentTotal ? `<span class="meta font-medium">(${parentTotal.toLocaleString('id-ID')} ${metricLabel} total)</span>` : '')}
        <button type="button" class="text-button" id="btn-clear-drilldown" title="Hapus filter drill-down utama">${icon('close')}</button>
      </span>
    ` : ''}
    ${query.secondary_facet && query.secondary_facet_value ? `
      <span class="badge primary">
        Pivot Kedua: <strong>${esc(query.secondary_facet)} = ${esc(query.secondary_facet_value)}</strong>
        ${secPct !== undefined && secPct !== null ? `
          <span class="filter-pct primary-pct">
            ${(filteredCount || 0).toLocaleString('id-ID')} ${metricLabel} · ${secPct}% dari ${esc(query.facet_value || 'utama')}
            ${totPct ? `(${totPct}% total)` : ''}
          </span>
        ` : ''}
        <button type="button" class="text-button" id="btn-clear-secondary-drilldown" title="Hapus filter drill-down kedua">${icon('close')}</button>
      </span>
    ` : ''}
  `;
}

export function statsPage(query) {
  const pivotOpts = PIVOT_OPTIONS.map(([val, label]) => `<option value="${val}" ${query.pivot_by === val ? 'selected' : ''}>${esc(label)}</option>`).join('');
  const secPivotOpts = [
    ['', 'Tidak ada (satu level)'],
    ...PIVOT_OPTIONS.filter(([val]) => val !== 'pattern' && val !== query.pivot_by),
  ].map(([val, label]) => `<option value="${val}" ${query.secondary_pivot === val ? 'selected' : ''}>${esc(label)}</option>`).join('');

  const topNOpts = [
    [500, 'Semua kategori'],
    [100, 'Maks 100 kategori'],
    [50, 'Maks 50 kategori'],
    [25, 'Maks 25 kategori'],
  ].map(([n, l]) => `<option value="${n}" ${query.top_n === n ? 'selected' : ''}>${l}</option>`).join('');
  const timePresets = [
    ['', 'Semua waktu'],
    ['1h', '1 jam terakhir'],
    ['24h', '24 jam terakhir'],
    ['7d', '7 hari terakhir'],
    ['30d', '30 hari terakhir'],
    ['custom', 'Rentang kustom…'],
  ].map(([v, l]) => `<option value="${v}" ${query.time_preset === v ? 'selected' : ''}>${l}</option>`).join('');

  const triageUrl = triageRouteFromStats(query);

  return `
    <header class="page-header">
      <div class="page-heading">
        <h1 id="stats-title">Statistik &amp; Pivot</h1>
        <p class="page-description">Workbench investigasi analitis berbasis agregasi telemetri SQL murni.</p>
      </div>
      <div class="page-actions stats-page-actions"><details class="format-menu"><summary class="button">Ekspor ${icon('down')}</summary><div>
        <button class="button" type="button" data-action="export-csv">${icon('report')} CSV</button>
        <button class="button" type="button" data-action="export-svg">${icon('copy')} SVG</button>
        <button class="button" type="button" data-action="copy-summary">${icon('copy')} Salin Ringkasan</button>
        </div></details>
        <a class="button" id="btn-open-triage" href="${triageUrl}">${icon('inbox')} Buka di Triage</a>
        <button class="button" type="button" data-action="reset-stats">${icon('refresh')} Reset</button>
      </div>
    </header>

    <section class="panel stats-controls stack">
      <div class="stats-control-row">
        <div class="field stats-field-grow">
          <label for="stats-pivot">Kelompokkan berdasarkan</label>
          <select class="select" id="stats-pivot" name="pivot_by">${pivotOpts}</select>
        </div>
        <div class="field stats-field-grow">
          <label for="stats-time">Rentang waktu</label>
          <select class="select" id="stats-time" name="time_preset">${timePresets}</select>
        </div>
        <div class="field stats-field-auto">
          <label for="stats-metric-segmented">Metrik hitungan</label>
          <div class="segmented stats-segmented" id="stats-metric-segmented">
            ${METRIC_OPTIONS.map(([val, lbl]) => `<button type="button" class="btn-seg ${query.metric === val ? 'active' : ''}" data-metric="${val}" aria-pressed="${query.metric === val}">${esc(lbl)}</button>`).join('')}
          </div>
        </div>
      </div>

      <details class="stats-advanced" ${query.secondary_pivot || query.top_n !== 500 ? 'open' : ''}><summary>Pengaturan lanjutan</summary>
      <div class="stats-control-row">
        <div class="field stats-field-grow">
          <label for="stats-secondary-pivot">Pivot kedua (stacked bar)</label>
          <select class="select" id="stats-secondary-pivot" name="secondary_pivot">${secPivotOpts}</select>
        </div>

        <div class="field stats-field-grow">
          <label for="stats-top-n">Batas kategori teratas</label>
          <select class="select" id="stats-top-n" name="top_n">${topNOpts}</select>
        </div>
        <div class="field stats-field-grow">
          <label for="stats-preset-select">Preset tersimpan</label>
          <div class="stats-preset-control">
            <select class="select" id="stats-preset-select">
              <option value="">Pilih preset…</option>
              <option value="preset-top-rules-24h">Top Rules 24 Jam</option>
              <option value="preset-top-ips-7d">Top IP Sumber 7 Hari</option>
              <option value="preset-http-status">Distribusi HTTP Status</option>
            </select>
            <button class="button icon-button" type="button" id="btn-save-preset" title="Simpan konfigurasi tampilan saat ini">${icon('plus')}</button>
          </div>
        </div>
      </div>

      </details>
      <div id="stats-custom-time-wrap" class="stats-custom-time" style="display:${query.time_preset === 'custom' || (query.time_from && !query.time_preset) ? 'grid' : 'none'}">
        <div class="field">
          <label for="stats-time-from">Dari waktu</label>
          <input class="input" type="datetime-local" id="stats-time-from" value="${esc(query.time_from)}">
        </div>
        <div class="field">
          <label for="stats-time-to">Sampai waktu</label>
          <input class="input" type="datetime-local" id="stats-time-to" value="${esc(query.time_to)}">
        </div>
      </div>

      <div id="stats-pattern-wrap" class="field stats-pattern-wrap" style="display:${query.pivot_by === 'pattern' ? 'block' : 'none'}">
        <label for="stats-pattern-input">Kata kunci / pola teks (pencarian literal)</label>
        <div class="stats-pattern-row">
          <input class="input" type="text" id="stats-pattern-input" value="${esc(query.pattern)}" placeholder="Contoh: sqlmap, bot, /admin, 403..." maxlength="120">
          <button class="button" type="button" id="btn-apply-pattern">Terapkan Pola</button>
        </div>
      </div>

      <div id="stats-applied-filters" class="applied-filters" style="display:${(query.facet && query.facet_value) || (query.secondary_facet && query.secondary_facet_value) ? 'flex' : 'none'}">
        ${renderAppliedFilters(query, null)}
      </div>
    </section>

    <div class="stats-chart-toolbar">
        <div class="field stats-field-auto">
          <label for="stats-chart-segmented">Tipe visualisasi</label>
          <div class="segmented stats-segmented" id="stats-chart-segmented">
            ${CHART_OPTIONS.map(([val, lbl]) => `<button type="button" class="btn-seg ${query.chart === val ? 'active' : ''}" data-chart="${val}" aria-pressed="${query.chart === val}">${esc(lbl)}</button>`).join('')}
          </div>
        </div>
    </div>
    <div id="stats-workspace" class="stack">
      <div id="stats-results"></div>
    </div>

    <dialog class="app-dialog" id="stats-batch-incident-dialog" aria-labelledby="stats-batch-incident-title">
      <div class="dialog-header">
        <h2 id="stats-batch-incident-title">Masukkan Bukti ke Insiden</h2>
        <button class="button icon-button" data-close-stats-batch-incident aria-label="Tutup dialog">${icon('close')}</button>
      </div>
      <form id="stats-batch-incident-form" class="stack">
        <p class="muted"><span id="stats-batch-incident-count">0</span> alert terpilih dari hasil drill-down akan ditautkan ke kasus insiden di bawah ini.</p>
        <div class="field">
          <div class="split" style="margin-bottom:4px">
            <label for="stats-batch-incident-select" style="margin-bottom:0">Pilih Insiden Sasaran</label>
            <button type="button" class="text-button meta" id="btn-reload-batch-incidents" title="Muat ulang daftar insiden">${icon('refresh')} Muat ulang</button>
          </div>
          <select class="select" id="stats-batch-incident-select" name="group_id" required>
            <option value="">Memuat daftar insiden…</option>
          </select>
          <div id="stats-batch-incident-hint" class="meta" style="margin-top:6px;"></div>
        </div>
        <div class="dialog-actions" style="margin-top:20px; display:flex; justify-content:flex-end; gap:8px;">
          <button type="button" class="button" data-close-stats-batch-incident>Batal</button>
          <button class="button primary" type="submit">Tautkan ke Insiden</button>
        </div>
      </form>
    </dialog>
  `;
}

export function statsResults(data, query, {drilldownAlerts = null, selectedIds = [], expandedLogIds = new Set(), showAllLogs = false, selectedSecondaryKeys = [], showAllSecondary = false} = {}) {
  const total = Number(data.total) || 0;
  const metricLabel = data.metric === 'events' ? 'event' : 'alert';
  const items = distributionPercentages(data.items || [], 0, total);
  const topCount = items[0]?.count || 0;
  const topItems = items.filter(it => it.count === topCount && topCount > 0);
  const isTie = topItems.length > 1;

  let chartHtml = '';
  if (query.chart === 'bar') {
    const secLabel = data.secondary_pivot ? (PIVOT_OPTIONS.find(([k]) => k === data.secondary_pivot)?.[1] || data.secondary_pivot) : '';
    chartHtml = renderBarChart({
      items,
      total,
      metric: data.metric,
      secondaryDistribution: data.secondary_distribution,
      secondaryLabel: secLabel,
      showAllSecondary,
    });
  } else if (query.chart === 'donut') {
    chartHtml = renderDonutChart({items, total, metric: data.metric});
  } else if (query.chart === 'line') {
    chartHtml = renderLineChart({timeSeries: data.time_series || [], topKeys: items.map(it => it.key), metric: data.metric});
  }

  const tableRows = items.map(item => {
    const keyEsc = esc(item.key);
    const triageUrl = triageRouteFromStats(query, {facet: data.pivot_by, facet_value: item.key});
    const subDist = data.secondary_distribution?.[item.key] || [];
    const subBreakdown = subDist.length ? `
      <div class="meta sub-breakdown">
        ${subDist.slice(0, 3).map(s => `${esc(s.key)} (${s.count})`).join(' · ')}
        ${subDist.length > 3 ? ` · +${subDist.length - 3} lainnya` : ''}
      </div>
    ` : '';

    return `
      <tr>
        <td class="mono font-medium">
          ${keyEsc}
          ${subBreakdown}
        </td>
        <td class="numeric">${item.count.toLocaleString('id-ID')}</td>
        <td class="numeric">
          ${item.displayPercentage}%
          ${query.facet && query.facet_value && data.primary_percentage_of_total !== undefined ? `
            <div class="meta font-medium sub-breakdown-pct">(${data.primary_percentage_of_total}% workspace)</div>
          ` : ''}
        </td>
        <td class="actions-col" style="text-align:right;">
          <button type="button" class="button text-button" data-drill-key="${keyEsc}" title="Saring statistik dan tampilkan bukti alert">Drill-down</button>
          <a class="button text-button" href="${triageUrl}" title="Lihat di antrean Triage">Triage</a>
        </td>
      </tr>
    `;
  }).join('');

  let secondaryBreakdownSection = '';
  if (data.secondary_breakdown && data.secondary_breakdown.length) {
    const secLabel = data.secondary_pivot ? (PIVOT_OPTIONS.find(([k]) => k === data.secondary_pivot)?.[1] || data.secondary_pivot) : 'Pivot Kedua';
    const activeSubCat = query.secondary_facet_value;

    let sortedBreakdown = [...(data.secondary_breakdown || [])].sort((a, b) => {
      const cDiff = (b.count || 0) - (a.count || 0);
      if (cDiff !== 0) return cDiff;
      return String(a.key || '').localeCompare(String(b.key || ''));
    });

    const hasMoreThan10 = sortedBreakdown.length > 10;
    const isShowingAll = Boolean(showAllSecondary);

    let visibleBreakdown = activeSubCat
      ? sortedBreakdown.filter(sb => sb.key === activeSubCat)
      : (hasMoreThan10 && !isShowingAll ? sortedBreakdown.slice(0, 10) : sortedBreakdown);

    if (activeSubCat && visibleBreakdown.length === 0) {
      visibleBreakdown = [{
        key: activeSubCat,
        count: data.total || 0,
        percentage: data.secondary_percentage_of_parent || 0,
      }];
    }

    const selectedSecSet = new Set(selectedSecondaryKeys);
    const allSecSelected = visibleBreakdown.length > 0 && selectedSecondaryKeys.length === visibleBreakdown.length;
    const primaryCategoryTotal = data.secondary_breakdown.reduce((acc, sb) => acc + (sb.count || 0), 0) || total || 1;
    const totalSelectedAlerts = visibleBreakdown
      .filter(sb => selectedSecSet.has(sb.key))
      .reduce((acc, sb) => acc + (sb.count || 0), 0);
    const selectedPercentage = Math.round((totalSelectedAlerts / primaryCategoryTotal) * 1000) / 10;

    const secRows = visibleBreakdown.map(sb => {
      const isFiltered = activeSubCat === sb.key;
      const isChecked = selectedSecSet.has(sb.key);
      const isMalicious = isMaliciousPath(sb.key);
      const keyEsc = esc(sb.key);
      const pct = (sb.percentage !== undefined && sb.percentage !== null)
        ? sb.percentage
        : Math.round(((sb.count || 0) / primaryCategoryTotal) * 1000) / 10;
      return `
        <tr class="${isFiltered ? 'is-selected' : ''} ${isMalicious ? 'has-malicious-match' : ''}">
          <td style="width:40px;">
            <input type="checkbox" data-select-secondary-key="${keyEsc}" ${isChecked ? 'checked' : ''} aria-label="Pilih sub-kategori ${keyEsc}">
          </td>
          <td class="mono font-medium">
            ${keyEsc}
            ${isMalicious ? `<span class="badge danger malicious-badge" title="Terdeteksi oleh Malicious Spotter">Mencurigakan</span>` : ''}
          </td>
          <td class="numeric">${sb.count.toLocaleString('id-ID')}</td>
          <td class="numeric">${pct}%</td>
          <td class="actions-col" style="text-align:right; white-space:nowrap;">
            <button type="button" class="button text-button ${isFiltered ? 'primary' : ''}"
                    data-secondary-drill-key="${keyEsc}"
                    title="Saring hanya kategori kedua: ${keyEsc}">
              ${isFiltered ? 'Terpilih (Saring)' : 'Drill-down'}
            </button>
            <button type="button" class="button text-button"
                    data-action="add-secondary-to-incident"
                    data-secondary-key="${keyEsc}"
                    data-count="${sb.count}"
                    title="Langsung masukkan semua ${sb.count} alert pada sub-kategori ini ke insiden">
              ${icon('cases')} + Insiden
            </button>
          </td>
        </tr>
      `;
    }).join('');

    secondaryBreakdownSection = `
      <section class="panel table-container secondary-breakdown-section">
        <div class="section-heading stats-section-heading">
          <div>
            <h3>Rincian ${esc(secLabel)} (dalam "${esc(query.facet_value)}")</h3>
            <span class="meta">
              ${activeSubCat ? `
                Menyaring 1 sub-kategori (dari total ${data.secondary_breakdown.length} dalam "${esc(query.facet_value)}")
                ${data.parent_total ? ` · Basis: ${data.parent_total.toLocaleString('id-ID')} ${metricLabel}` : ''}
                ${data.secondary_percentage_of_parent !== undefined && data.secondary_percentage_of_parent !== null ? ` · Proporsi: <strong class="sub-breakdown-pct">${data.secondary_percentage_of_parent}%</strong> (${(data.total || 0).toLocaleString('id-ID')} ${metricLabel})` : ''}
              ` : `
                ${data.secondary_breakdown.length} sub-kategori ditemukan
                ${data.parent_total ? ` · Basis: ${data.parent_total.toLocaleString('id-ID')} ${metricLabel}` : ''}
                ${data.primary_percentage_of_total !== undefined ? ` (<strong>${data.primary_percentage_of_total}%</strong> dari workspace)` : ''}
              `}
            </span>
          </div>
          <div class="stats-section-actions">
            ${activeSubCat ? `
              <button type="button" class="button primary" id="btn-clear-secondary-drilldown">
                ${icon('refresh')} Tampilkan Semua Sub-kategori (${data.secondary_breakdown.length})
              </button>
            ` : `
              <button type="button" class="button" id="btn-malicious-spotter" title="Pilih otomatis semua sub-kategori yang mengandung pola mencurigakan (.env, credential, xmlrpc, config, git, admin, dll)">
                ${icon('alert')} Malicious Spotter
              </button>
              <button type="button" class="button" id="btn-benign-spotter" title="Pilih otomatis semua sub-kategori yang tidak mengandung pola berbahaya (kebalikan dari Malicious Spotter)">
                ${icon('check')} Benign Spotter
              </button>
            `}
          </div>
        </div>

        <div id="secondary-selection-toolbar" class="selection-toolbar" style="display:${selectedSecondaryKeys.length ? 'flex' : 'none'}">
          <strong>${selectedSecondaryKeys.length} sub-kategori dipilih (${totalSelectedAlerts.toLocaleString('id-ID')} ${metricLabel} · ${selectedPercentage}%)</strong>
          <button class="button primary" type="button" data-action="batch-secondary-create-incident">${icon('plus')} Buat insiden</button>
          <button class="button" type="button" data-action="batch-secondary-add-incident">${icon('cases')} Masukkan ke insiden</button>
          <button class="button" type="button" data-action="batch-secondary-review">Tandai direview</button>
          <button class="button icon-button" type="button" data-action="clear-secondary-selection" aria-label="Batalkan pilihan sub-kategori">${icon('close')}</button>
        </div>

        <div class="table-region" tabindex="0" role="region" aria-label="Tabel analisis; gulir horizontal untuk kolom lainnya">
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:40px;">
                  <input type="checkbox" id="stats-select-all-secondary" ${allSecSelected ? 'checked' : ''} aria-label="Pilih semua sub-kategori">
                </th>
                <th>${esc(secLabel)}</th>
                <th class="numeric" style="width:120px;">${data.metric === 'events' ? 'Event' : 'Alert'}</th>
                <th class="numeric" style="width:100px;">Proporsi</th>
                <th style="width:180px; text-align:right;">Aksi</th>
              </tr>
            </thead>
            <tbody>
              ${secRows}
            </tbody>
          </table>
        </div>
        ${hasMoreThan10 && !activeSubCat ? `
          <div class="secondary-toggle-row" style="margin-top:12px; display:flex; justify-content:center;">
            <button type="button" class="button" id="btn-toggle-all-secondary" data-stats-action="toggle-all-secondary" aria-expanded="${isShowingAll}">
              ${icon(isShowingAll ? 'down' : 'chevron')} <span id="toggle-all-secondary-label">${isShowingAll ? 'Tampilkan lebih sedikit' : 'Tampilkan semua'}</span>
            </button>
          </div>
        ` : ''}
      </section>
    `;
  }

  let drilldownSection = '';
  if (drilldownAlerts && drilldownAlerts.length) {
    const selectedSet = new Set(selectedIds);
    const allSelected = selectedIds.length > 0 && selectedIds.length === drilldownAlerts.length;

    const drilldownRows = drilldownAlerts.map(a => {
      const isSel = selectedSet.has(a.id);
      const isExp = showAllLogs || expandedLogIds.has(a.id);
      const isMal = isMaliciousAlert(a);
      const logText = a.full_log || a.raw?.full_log || (a.raw ? JSON.stringify(a.raw, null, 2) : 'Log tidak tersedia.');

      const mainRow = `
        <tr data-drilldown-row="${a.id}" class="${isSel ? 'is-selected' : ''} ${isMal ? 'has-malicious-match' : ''}">
          <td style="width:40px;">
            <input type="checkbox" data-select-drilldown="${a.id}" ${isSel ? 'checked' : ''} aria-label="Pilih alert #${a.id}">
          </td>
          <td class="meta num">${esc(a.timestamp?.slice(0, 16).replace('T', ' ') || '—')}</td>
          <td>${severity(a.rule_level)}</td>
          <td>
            <span class="font-medium">${esc(a.description || 'Alert')}</span>
            <span class="meta mono">(${esc(a.rule_id || '—')})</span>
            ${isMal ? `<span class="badge danger malicious-badge" title="Terindikasi Malicious">Mencurigakan</span>` : ''}
            <button type="button" class="text-button meta log-toggle-btn" data-stats-action="toggle-log" data-alert-id="${a.id}" aria-expanded="${isExp}" title="Buka/tutup full log">
              [${isExp ? 'Tutup Log' : 'Log'}]
            </button>
          </td>
          <td class="mono">${esc(a.source_ip || '—')}</td>
          <td style="text-align:right;">
            <a class="button text-button" href="#/triage?alert=${a.id}" title="Buka detail lengkap di Triage">Triage</a>
          </td>
        </tr>
      `;

      const logRow = isExp ? `
        <tr class="log-expansion-row" data-log-for="${a.id}">
          <td colspan="6" class="log-expansion-cell">
            <div class="queue-log-box stack">
              <div class="split queue-log-head">
                <span class="meta mono">Log Alert #${esc(a.alert_id || a.id)} · Host: ${esc(a.agent_name || '—')} · Rule ${esc(a.rule_id || '—')}</span>
                <div class="stats-log-actions">
                  <button class="button text-button meta" type="button" data-stats-action="copy-single-log" data-alert-id="${a.id}">${icon('copy')} Salin</button>
                  <button class="button text-button meta" type="button" data-stats-action="copy-single-redacted" data-alert-id="${a.id}">Tersamarkan</button>
                  <button class="button text-button meta" type="button" data-stats-action="copy-single-defanged" data-alert-id="${a.id}">Defang</button>
                </div>
              </div>
              <pre class="raw-log">${esc(logText)}</pre>
            </div>
          </td>
        </tr>
      ` : '';

      return mainRow + logRow;
    }).join('');

    drilldownSection = `
      <section class="panel stack drilldown-evidence-section">
        <div class="section-heading stats-section-heading">
          <div>
            <h2>Bukti Alert Hasil Drill-down</h2>
            <span class="meta">
              ${drilldownAlerts.length} alert ditampilkan (${esc(query.facet)} = "${esc(query.facet_value)}"${query.secondary_facet_value ? ` · ${esc(query.secondary_facet)} = "${esc(query.secondary_facet_value)}"` : ''})
              ${data && data.secondary_percentage_of_parent !== undefined && data.secondary_percentage_of_parent !== null ? `
                — <strong class="sub-breakdown-pct">${data.secondary_percentage_of_parent}%</strong> dari "${esc(query.facet_value)}"
                ${data.secondary_percentage_of_total ? `(<strong>${data.secondary_percentage_of_total}%</strong> total workspace)` : ''}
              ` : ''}
            </span>
          </div>
          <div class="stats-section-actions">
            <button type="button" class="button" id="btn-evidence-malicious-spotter" title="Pilih otomatis semua alert individual yang terindikasi berbahaya">
              ${icon('alert')} Malicious Spotter
            </button>
            <button type="button" class="button" id="btn-evidence-benign-spotter" title="Pilih otomatis semua alert individual yang bersih/jinak">
              ${icon('check')} Benign Spotter
            </button>
            <button type="button" class="button" id="btn-toggle-all-stats-logs" aria-pressed="${showAllLogs}">
              ${icon('cases')} <span id="toggle-all-logs-label">${showAllLogs ? 'Tutup semua log' : 'Semua log'}</span>
            </button>
          </div>
        </div>

        <div id="stats-selection-toolbar" class="selection-toolbar" style="display:${selectedIds.length ? 'flex' : 'none'};">
          <strong>${selectedIds.length} alert dipilih</strong>
          <button class="button primary" type="button" data-stats-action="create-incident">${icon('plus')} Buat insiden</button>
          <button class="button" type="button" data-stats-action="add-to-incident">${icon('cases')} Masukkan ke insiden</button>
          <button class="button" type="button" data-stats-action="batch-review">Tandai direview</button>
          <button class="button" type="button" data-stats-action="batch-unreview">Belum direview</button>
          <button class="button" type="button" data-stats-action="copy-logs">${icon('copy')} Salin log</button>
          <button class="button" type="button" data-stats-action="copy-redacted">Tersamarkan</button>
          <button class="button icon-button" type="button" data-stats-action="clear-selection" aria-label="Batalkan pilihan">${icon('close')}</button>
        </div>

        <div class="table-region" tabindex="0" role="region" aria-label="Tabel analisis; gulir horizontal untuk kolom lainnya">
          <table class="data-table">
            <thead>
              <tr>
                <th style="width:40px;"><input type="checkbox" id="stats-select-all-drilldown" ${allSelected ? 'checked' : ''} aria-label="Pilih semua alert hasil drill-down"></th>
                <th style="width:110px;">Waktu</th>
                <th style="width:90px;">Severity</th>
                <th>Deskripsi / Rule</th>
                <th style="width:140px;">Source IP</th>
                <th style="width:100px; text-align:right;">Aksi</th>
              </tr>
            </thead>
            <tbody>
              ${drilldownRows}
            </tbody>
          </table>
        </div>
      </section>
    `;
  } else if (query.facet && query.facet_value) {
    drilldownSection = `
      <section class="panel stack drilldown-evidence-section">
        <div class="section-heading">
          <div>
            <h2>Bukti Alert Hasil Drill-down</h2>
            <span class="meta">0 alert ditemukan (${esc(query.facet)} = "${esc(query.facet_value)}"${query.secondary_facet_value ? ` · ${esc(query.secondary_facet)} = "${esc(query.secondary_facet_value)}"` : ''})</span>
          </div>
        </div>
        <p class="muted" style="padding:16px;">Tidak ada alert yang cocok dengan kriteria filter drill-down ini.</p>
      </section>
    `;
  }

  return `
    <div class="metric-strip">
      <div>
        <dt>Total ${metricLabel}</dt>
        <dd>
        ${total.toLocaleString('id-ID')}
        ${data.workspace_total && data.workspace_total !== total ? `
          <span class="meta metric-total-note"> (${data.primary_percentage_of_total !== undefined ? `${data.primary_percentage_of_total}% dari ` : ''}${data.workspace_total.toLocaleString('id-ID')} total)</span>
          ` : ''}
        </dd>
      </div>
      <div>
        <dt>Total Kategori Unik</dt>
        <dd>${items.length} <span class="meta metric-unit">kategori</span></dd>
      </div>
      <div>
        <dt>Kategori Terbanyak ${isTie ? `<span class="meta font-medium">(${topItems.length} kategori seri)</span>` : ''}</dt>
        <dd class="metric-category">
          <strong>${topCount.toLocaleString('id-ID')} <span class="meta">${metricLabel}${isTie ? ' masing-masing' : ''}</span></strong>
          <span class="metric-category-name" title="${topItems.map(it => esc(it.key)).join(', ')}">
            ${isTie ? topItems.map(it => `<span class="badge neutral">${esc(it.key)}</span>`).join(' ') : (items[0] ? esc(items[0].key) : '—')}
          </span>
        </dd>
      </div>
      ${query.facet && query.facet_value && data.primary_percentage_of_total !== undefined && data.primary_percentage_of_total !== null && !query.secondary_facet_value ? `
        <div>
          <dt>Proporsi Pivot Utama</dt>
          <dd class="metric-proportion">${data.primary_percentage_of_total}% <span class="meta metric-unit">(${total.toLocaleString('id-ID')} dari ${data.workspace_total?.toLocaleString('id-ID') || 0} ${metricLabel})</span></dd>
        </div>
      ` : ''}
      ${query.secondary_facet_value && data.secondary_percentage_of_parent !== undefined && data.secondary_percentage_of_parent !== null ? `
        <div>
          <dt>Proporsi Pivot Kedua</dt>
          <dd class="metric-proportion">${data.secondary_percentage_of_parent}% <span class="meta metric-unit">(${total.toLocaleString('id-ID')} dari ${data.parent_total?.toLocaleString('id-ID') || 0} ${metricLabel})</span></dd>
        </div>
      ` : ''}
    </div>

    ${query.chart !== 'table' ? `
      <section class="panel chart-container" id="stats-chart-wrapper" tabindex="0" aria-label="Grafik statistik; gulir horizontal pada layar kecil">
        ${chartHtml}
      </section>
    ` : ''}

    <section class="panel table-container">
      <div class="section-heading">
        <h2>Tabel Distribusi Pivot</h2>
        <span class="meta">
          ${items.length} baris ditampilkan
          ${query.facet && query.facet_value && data.primary_percentage_of_total !== undefined ? ` · <strong>${data.primary_percentage_of_total}%</strong> dari total workspace (${data.workspace_total?.toLocaleString('id-ID')} ${metricLabel})` : ''}
        </span>
      </div>
      <div class="table-region" tabindex="0" role="region" aria-label="Tabel analisis; gulir horizontal untuk kolom lainnya">
        <table class="data-table">
          <thead>
            <tr>
              <th>Nilai / Kategori</th>
              <th class="numeric" style="width:120px;">${data.metric === 'events' ? 'Event' : 'Alert'}</th>
              <th class="numeric" style="width:100px;">Proporsi</th>
              <th style="width:150px; text-align:right;">Aksi</th>
            </tr>
          </thead>
          <tbody>
            ${tableRows}
          </tbody>
        </table>
      </div>
    </section>

    ${secondaryBreakdownSection}

    ${drilldownSection}
  `;
}
