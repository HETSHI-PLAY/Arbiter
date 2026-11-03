import {esc, icon} from './primitives.js';

const SIGNAL_COLORS = {
  critical: 'var(--critical)',
  high: 'var(--critical)',
  medium: 'var(--warning)',
  low: 'var(--info)',
  default: 'var(--control)',
  accent1: '#7aa2f7',
  accent2: '#bb9af7',
  accent3: '#7dcfff',
  accent4: '#e0af68',
  accent5: '#9ece6a',
  accent6: '#f7768e',
  accent7: '#2ac3de',
  accent8: '#b4f9f8',
  other: 'var(--muted)',
};

const PALETTE = [
  SIGNAL_COLORS.accent1,
  SIGNAL_COLORS.accent2,
  SIGNAL_COLORS.accent3,
  SIGNAL_COLORS.accent4,
  SIGNAL_COLORS.accent5,
  SIGNAL_COLORS.accent6,
  SIGNAL_COLORS.accent7,
  SIGNAL_COLORS.accent8,
];

export function getColor(key, index = 0) {
  const lk = String(key || '').toLowerCase();
  if (lk === 'critical') return SIGNAL_COLORS.critical;
  if (lk === 'high') return SIGNAL_COLORS.high;
  if (lk === 'medium') return SIGNAL_COLORS.medium;
  if (lk === 'low') return SIGNAL_COLORS.low;
  if (lk === 'lainnya') return SIGNAL_COLORS.other;
  return PALETTE[index % PALETTE.length];
}

export function renderBarChart({
  items = [],
  otherCount = 0,
  otherPercentage = 0,
  total = 0,
  metric = 'alerts',
  secondaryDistribution = null,
  secondaryLabel = '',
  showAllSecondary = false,
} = {}) {
  const metricLabel = metric === 'events' ? 'event' : 'alert';
  const allRows = [...items];
  if (!allRows.length || total <= 0) {
    return `<div class="chart-empty"><p class="muted">Tidak ada data untuk ditampilkan pada grafik ini.</p></div>`;
  }

  const rowHeight = 44;
  const height = allRows.length * rowHeight + 32;
  const width = 960;
  const labelWidth = 350;
  const barMaxWidth = width - labelWidth - 120;

  // Gather and sort unique secondary keys for global legend by aggregate count desc, key asc
  let secondaryLegend = '';
  if (secondaryDistribution) {
    const secKeyCounts = new Map();
    for (const subList of Object.values(secondaryDistribution)) {
      for (const s of (subList || [])) {
        if (s.key) {
          secKeyCounts.set(s.key, (secKeyCounts.get(s.key) || 0) + (s.count || 0));
        }
      }
    }

    const sortedSecEntries = [...secKeyCounts.entries()].sort((a, b) => {
      const cDiff = b[1] - a[1];
      if (cDiff !== 0) return cDiff;
      return String(a[0]).localeCompare(String(b[0]));
    });

    if (sortedSecEntries.length > 0) {
      const hasMoreThan10 = sortedSecEntries.length > 10;
      const isExpanded = Boolean(showAllSecondary);
      const visibleEntries = (!isExpanded && hasMoreThan10)
        ? sortedSecEntries.slice(0, 10)
        : sortedSecEntries;

      const chips = visibleEntries.map(([k, count], idx) => `
        <button type="button" class="button text-button legend-chip" data-secondary-legend-key="${esc(k)}" style="display:inline-flex; align-items:center; gap:5px; padding:3px 7px; font-size:12px; border-radius:4px;" title="Saring hanya kategori kedua: ${esc(k)} (${count.toLocaleString('id-ID')} ${metricLabel})">
          <span style="width:10px; height:10px; border-radius:2px; background:${getColor(k, idx)}; flex:none;" aria-hidden="true"></span>
          <span class="mono">${esc(k)}</span>
          <span class="muted font-mono" style="font-size:11px; opacity:0.8;">(${count.toLocaleString('id-ID')})</span>
        </button>
      `).join('');

      const toggleBtn = hasMoreThan10 ? `
        <button type="button" class="button text-button" data-stats-action="toggle-all-secondary" aria-expanded="${isExpanded}" style="font-size:11px; padding:3px 8px; margin-left:auto; display:inline-flex; align-items:center; gap:4px;">
          ${icon(isExpanded ? 'down' : 'chevron')} <span>${isExpanded ? 'Tampilkan lebih sedikit' : `Tampilkan semua (${sortedSecEntries.length})`}</span>
        </button>
      ` : '';

      secondaryLegend = `
        <div class="chart-secondary-legend" style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:14px; font-size:12px; padding:8px 12px; background:var(--bg-surface); border:1px solid var(--border-subtle); border-radius:var(--radius-sm, 6px);">
          <span class="meta font-medium" style="margin-right:4px;">${hasMoreThan10 && !isExpanded ? `Top 10 ${esc(secondaryLabel || 'Pivot Kedua')}:` : `Pecahan ${esc(secondaryLabel || 'Pivot Kedua')} (${sortedSecEntries.length}):`}</span>
          ${chips}
          ${toggleBtn}
        </div>
      `;
    }
  }

  const bars = allRows.map((r, i) => {
    const y = i * rowHeight + 15;
    const pct = Number(r.displayPercentage ?? ((r.count / total) * 100)) || 0;
    const barW = Math.max(2, Math.round((pct / 100) * barMaxWidth));
    const keyEsc = esc(r.key);

    const subList = secondaryDistribution?.[r.key];
    let rects = '';
    if (subList && subList.length > 0) {
      let curX = labelWidth;
      const subTotal = subList.reduce((acc, s) => acc + (s.count || 0), 0) || r.count || 1;

      const sortedSubList = [...subList].sort((a, b) => {
        const cDiff = (b.count || 0) - (a.count || 0);
        if (cDiff !== 0) return cDiff;
        return String(a.key || '').localeCompare(String(b.key || ''));
      });

      const hasMoreThan10Sub = sortedSubList.length > 10;
      const isExpanded = Boolean(showAllSecondary);
      const visibleSubList = (!isExpanded && hasMoreThan10Sub)
        ? sortedSubList.slice(0, 10)
        : sortedSubList;

      const remainderCount = (!isExpanded && hasMoreThan10Sub)
        ? sortedSubList.slice(10).reduce((acc, s) => acc + (s.count || 0), 0)
        : 0;

      rects = visibleSubList.map((sub, sIdx) => {
        const segW = Math.max(1, Math.round((sub.count / subTotal) * barW));
        const subColor = getColor(sub.key, sIdx);
        const subPct = Math.round((sub.count / (r.count || 1)) * 100);
        const rx = `
          <rect x="${curX}" y="${y + 4}" width="${segW}" height="22" fill="${subColor}" opacity="0.9"
                data-primary-key="${keyEsc}" data-secondary-key="${esc(sub.key)}" tabindex="0" role="button" aria-label="${keyEsc} → ${esc(sub.key)}: ${sub.count} ${metricLabel}" class="stacked-bar-seg" style="cursor:pointer;">
            <title>${keyEsc} → ${esc(sub.key)}: ${sub.count} ${metricLabel} (${subPct}% dari kategori ini) — Klik untuk saring</title>
          </rect>
        `;
        curX += segW;
        return rx;
      }).join('');

      if (remainderCount > 0) {
        const remW = Math.max(2, Math.round((remainderCount / subTotal) * barW));
        const remPct = Math.round((remainderCount / (r.count || 1)) * 100);
        rects += `
          <rect x="${curX}" y="${y + 4}" width="${remW}" height="22" fill="var(--border)" opacity="0.75"
                data-primary-key="${keyEsc}" data-stats-action="toggle-all-secondary" tabindex="0" role="button" aria-label="${keyEsc} → +${sortedSubList.length - 10} lainnya: ${remainderCount} ${metricLabel}" class="stacked-bar-seg stacked-bar-remainder" style="cursor:pointer;">
            <title>${keyEsc} → +${sortedSubList.length - 10} sub-kategori lainnya: ${remainderCount} ${metricLabel} (${remPct}% dari kategori ini) — Klik untuk membuka semua</title>
          </rect>
        `;
        curX += remW;
      }
    } else {
      const color = getColor(r.key, i);
      rects = `<rect x="${labelWidth}" y="${y + 4}" width="${barW}" height="22" rx="3" fill="${color}" opacity="0.85" />`;
    }

    return `
      <g class="chart-bar-row" data-chart-key="${keyEsc}" tabindex="0" role="button" aria-label="${keyEsc}: ${r.count} ${metricLabel} (${pct}%)">
        <title>${keyEsc}: ${r.count} ${metricLabel} (${pct}%)</title>
        <text x="${labelWidth - 12}" y="${y + 19}" text-anchor="end" fill="var(--text)" font-size="13" font-family="var(--font)">${keyEsc.length > 46 ? esc(keyEsc.slice(0, 44) + '…') : keyEsc}</text>
        ${rects}
        <text x="${labelWidth + barW + 10}" y="${y + 20}" fill="var(--muted)" font-size="12" font-family="var(--mono)">${r.count} ${metricLabel} (${pct}%)</text>
      </g>
    `;
  }).join('');

  return `
    ${secondaryLegend}
    <svg class="chart-svg bar-chart" viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img" aria-label="Grafik Balok Statistik (${total} ${metricLabel} total)">
      <title>Grafik Balok Distribusi Alert</title>
      <desc>Menampilkan distribusi per kategori dengan total ${total} ${metricLabel}.</desc>
      <line x1="${labelWidth}" y1="8" x2="${labelWidth}" y2="${height - 10}" stroke="var(--border)" stroke-width="1" />
      ${bars}
    </svg>
  `;
}

export function renderDonutChart({items = [], otherCount = 0, otherPercentage = 0, total = 0, metric = 'alerts'} = {}) {
  const metricLabel = metric === 'events' ? 'event' : 'alert';
  const allRows = [...items];
  if (!allRows.length || total <= 0) {
    return `<div class="chart-empty"><p class="muted">Tidak ada data untuk grafik donut.</p></div>`;
  }

  const size = 380;
  const cx = size / 2;
  const cy = size / 2;
  const rOuter = 145;
  const rInner = 90;

  let currentAngle = -Math.PI / 2;
  const paths = allRows.map((row, i) => {
    const pct = Number(row.displayPercentage ?? ((row.count / total) * 100)) || 0;
    const sliceAngle = (pct / 100) * (2 * Math.PI);
    const startAngle = currentAngle;
    const endAngle = currentAngle + sliceAngle;
    currentAngle = endAngle;

    const x1 = cx + rOuter * Math.cos(startAngle);
    const y1 = cy + rOuter * Math.sin(startAngle);
    const x2 = cx + rOuter * Math.cos(endAngle);
    const y2 = cy + rOuter * Math.sin(endAngle);

    const x3 = cx + rInner * Math.cos(endAngle);
    const y3 = cy + rInner * Math.sin(endAngle);
    const x4 = cx + rInner * Math.cos(startAngle);
    const y4 = cy + rInner * Math.sin(startAngle);

    const largeArc = sliceAngle > Math.PI ? 1 : 0;
    const d = `M ${x1} ${y1} A ${rOuter} ${rOuter} 0 ${largeArc} 1 ${x2} ${y2} L ${x3} ${y3} A ${rInner} ${rInner} 0 ${largeArc} 0 ${x4} ${y4} Z`;
    const color = getColor(row.key, i);
    const keyEsc = esc(row.key);

    return `
      <path class="donut-slice" d="${d}" fill="${color}" opacity="0.9" stroke="var(--surface)" stroke-width="2"
            tabindex="0" role="button" data-chart-key="${keyEsc}" aria-label="${keyEsc}: ${row.count} (${pct}%)">
        <title>${keyEsc}: ${row.count} ${metricLabel} (${pct}%)</title>
      </path>
    `;
  }).join('');

  const legend = allRows.map((row, i) => {
    const pct = Number(row.displayPercentage ?? ((row.count / total) * 100)) || 0;
    const color = getColor(row.key, i);
    const keyEsc = esc(row.key);
    return `
      <button type="button" class="chart-legend-item text-button" data-chart-key="${keyEsc}" style="display:flex; align-items:center; gap:8px; font-size:12px; margin:4px 0;">
        <span class="legend-swatch" style="width:10px; height:10px; border-radius:2px; background:${color}; flex:none;" aria-hidden="true"></span>
        <span class="legend-label" style="color:var(--text);">${keyEsc}</span>
        <span class="legend-val mono" style="color:var(--muted); margin-left:auto;">${row.count} (${pct}%)</span>
      </button>
    `;
  }).join('');

  return `
    <div class="donut-layout" style="display:flex; flex-wrap:wrap; align-items:center; justify-content:center; gap:24px;">
      <svg class="chart-svg donut-chart" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img" aria-label="Grafik Donut Distribusi (${total} ${metricLabel} total)">
        <title>Grafik Donut Distribusi Alert</title>
        <desc>Distribusi proporsional kategori alert.</desc>
        ${paths}
        <text x="${cx}" y="${cy - 4}" text-anchor="middle" font-size="20" font-weight="600" fill="var(--text)" font-family="var(--mono)">${total.toLocaleString('id-ID')}</text>
        <text x="${cx}" y="${cy + 16}" text-anchor="middle" font-size="11" fill="var(--muted)" font-family="var(--font)">${metricLabel}</text>
      </svg>
      <div class="donut-legend stack" style="max-width:320px; flex:1; min-width:200px;">
        ${legend}
      </div>
    </div>
  `;
}

export function renderLineChart({timeSeries = [], topKeys = [], metric = 'alerts'} = {}) {
  const metricLabel = metric === 'events' ? 'event' : 'alert';
  if (!timeSeries.length) {
    return `<div class="chart-empty"><p class="muted">Tidak ada data rentang waktu untuk grafik tren.</p></div>`;
  }

  const width = 840;
  const height = 320;
  const padLeft = 55;
  const padRight = 30;
  const padTop = 25;
  const padBottom = 45;

  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;

  const maxVal = Math.max(1, ...timeSeries.map(b => b.total || 0));
  const nPoints = timeSeries.length;
  const stepX = nPoints > 1 ? chartW / (nPoints - 1) : chartW / 2;

  // Grid lines
  const gridLines = [0, 0.25, 0.5, 0.75, 1.0].map(frac => {
    const y = padTop + chartH - frac * chartH;
    const val = Math.round(frac * maxVal);
    return `
      <line x1="${padLeft}" y1="${y}" x2="${width - padRight}" y2="${y}" stroke="var(--border)" stroke-dasharray="3 3" />
      <text x="${padLeft - 6}" y="${y + 4}" text-anchor="end" font-size="10" fill="var(--muted)" font-family="var(--mono)">${val}</text>
    `;
  }).join('');

  // Total trend line
  const points = timeSeries.map((d, i) => {
    const x = padLeft + (nPoints > 1 ? i * stepX : chartW / 2);
    const y = padTop + chartH - ((d.total || 0) / maxVal) * chartH;
    return {x, y, data: d};
  });

  const polyPoints = points.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');

  const dots = points.map(p => {
    const bStr = esc(p.data.bucket || '');
    const isSpike = Boolean(p.data.above_average);
    const stroke = isSpike ? 'var(--warning)' : 'var(--text)';
    const r = isSpike ? 5 : 3.5;
    const spikeLabel = isSpike ? `<text x="${p.x.toFixed(1)}" y="${(p.y - 10).toFixed(1)}" text-anchor="middle" font-size="9" fill="var(--warning)" font-family="var(--mono)">▲ Di atas rata-rata</text>` : '';
    return `
      <g>
        <circle class="line-point${isSpike ? ' line-point-spike' : ''}" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="${r}" fill="var(--ground)" stroke="${stroke}" stroke-width="${isSpike ? 2.5 : 2}"
                tabindex="0" role="graphics-symbol" aria-label="${bStr}: ${p.data.total} ${metricLabel}${isSpike ? ' (Di atas rata-rata)' : ''}">
          <title>${bStr}: ${p.data.total} ${metricLabel}${isSpike ? ' (Di atas rata-rata)' : ''}</title>
        </circle>
        ${spikeLabel}
      </g>
    `;
  }).join('');

  // X axis labels (sparse)
  const xLabels = points.filter((_, i) => i === 0 || i === nPoints - 1 || (nPoints > 4 && i === Math.floor(nPoints / 2))).map(p => {
    let lbl = p.data.bucket || '';
    if (lbl.length >= 16) lbl = lbl.slice(11, 16);
    else if (lbl.length >= 10) lbl = lbl.slice(5, 10);
    return `<text x="${p.x}" y="${height - 12}" text-anchor="middle" font-size="10" fill="var(--muted)" font-family="var(--mono)">${esc(lbl)}</text>`;
  }).join('');

  return `
    <svg class="chart-svg line-chart" viewBox="0 0 ${width} ${height}" width="100%" height="${height}" role="img" aria-label="Grafik Garis Tren Waktu">
      <title>Grafik Tren Waktu</title>
      <desc>Menampilkan fluktuasi total alert per interval waktu.</desc>
      ${gridLines}
      <polyline class="line-series" fill="none" stroke="var(--text)" stroke-width="2.5" stroke-linejoin="round" points="${polyPoints}" />
      ${dots}
      <line x1="${padLeft}" y1="${padTop + chartH}" x2="${width - padRight}" y2="${padTop + chartH}" stroke="var(--border)" stroke-width="1" />
      ${xLabels}
    </svg>
  `;
}
