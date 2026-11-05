export const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[char]));
const paths = {
  search: '<circle cx="7" cy="7" r="4.5"/><path d="m10.5 10.5 3 3"/>',
  inbox: '<path d="M2 3h12v10H2zM2 9h3l1 2h4l1-2h3"/>',
  cases: '<path d="M2 4h5l1-2h6v11H2z"/>',
  upload: '<path d="M8 11V2M4 6l4-4 4 4M2 10v4h12v-4"/>',
  report: '<path d="M4 1h6l3 3v11H3V1zM9 1v4h4M5 8h6M5 11h6"/>',
  filter: '<path d="M2 3h12L9 8v5l-2 1V8z"/>',
  chevron: '<path d="m6 3 5 5-5 5"/>',
  down: '<path d="m3 6 5 5 5-5"/>',
  close: '<path d="m4 4 8 8M12 4l-8 8"/>',
  menu: '<path d="M2 4h12M2 8h12M2 12h12"/>',
  refresh: '<path d="M13 6a5.2 5.2 0 1 0 0 4M13 2v4H9"/>',
  check: '<path d="m3 8 3 3 7-7"/>',
  plus: '<path d="M8 2v12M2 8h12"/>',
  copy: '<rect x="6" y="5" width="8" height="9" rx="1"/><path d="M10 5V2H2v9h4"/>',
  arrow: '<path d="M13 8H3m5-5L3 8l5 5"/>',
  external: '<path d="M9 2h5v5M14 2 7 9M6 3H2v11h11v-4"/>',
  more: '<circle cx="3" cy="8" r=".6"/><circle cx="8" cy="8" r=".6"/><circle cx="13" cy="8" r=".6"/>',
  shield: '<path d="M8 1 2 4v4c0 3 6 7 6 7s6-4 6-7V4z"/>',
  clock: '<circle cx="8" cy="8" r="6"/><path d="M8 4v4l3 2"/>',
  chart: '<path d="M2 13h12M4 10V7M8 10V4M12 10V5"/>',
  database: '<ellipse cx="8" cy="4" rx="6" ry="2.5"/><path d="M2 4v8c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5V4"/><path d="M2 8c0 1.4 2.7 2.5 6 2.5s6-1.1 6-2.5"/>',
  settings: '<circle cx="8" cy="8" r="2.2"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4"/>',
  pulse: '<path d="M1.5 8h3l2-5 3 10 2-5h3"/>',
  spark: '<path d="M8 1.5 9.4 6l4.6 1.4L9.4 9 8 13.5 6.6 9 2 7.4 6.6 6z"/><path d="M13 11.5 13.5 13l1.5.5-1.5.5L13 15.5l-.5-1.5L11 13.5l1.5-.5z"/>',
  delete: '<path d="M3 4h10M6 4V2h4v2M5 4v9h6V4"/>',
};
export function icon(name) { return `<svg class="icon" width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${paths[name] || paths.chevron}</svg>`; }
export function severity(value) {
  const key = typeof value === 'number' ? (value >= 12 ? 'critical' : value >= 10 ? 'high' : value >= 7 ? 'medium' : 'low') : String(value || 'low').toLowerCase();
  const label = {critical:'Critical', high:'High', medium:'Medium', low:'Low'}[key] || 'Unknown';
  return `<span class="badge ${['critical','high','medium','low'].includes(key) ? key : 'neutral'}"><span class="status-dot" aria-hidden="true"></span>${label}</span>`;
}
export function statusLabel(value) { return ({open:'Terbuka', in_progress:'Dalam investigasi', investigating:'Dalam investigasi', closed:'Ditutup', resolved:'Diselesaikan', reviewed:'Direview', unreviewed:'Belum direview', high:'High', critical:'Critical', medium:'Medium', low:'Low'})[value] || String(value || '—').replaceAll('_', ' '); }
export function formatTime(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return new Intl.DateTimeFormat('id-ID', {day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit', hourCycle:'h23'}).format(date);
}
export function emptyState(title, description, actionHTML = '') { return `<div class="empty-state"><h2>${esc(title)}</h2><p>${esc(description)}</p>${actionHTML ? `<div class="empty-actions">${actionHTML}</div>` : ''}</div>`; }
export function errorState(message) { return `<div class="error-region" role="alert"><strong>Tidak dapat memuat data</strong><p>${esc(message)}</p><button class="button" data-action="retry">Coba lagi</button></div>`; }
export function loadingRows(count = 5) { return `<div class="skeleton-list" aria-label="Memuat data" aria-busy="true">${Array.from({length:count}, () => '<div class="skeleton-row"><span></span><span></span><span></span></div>').join('')}</div>`; }
export function defangText(text) {
  if (!text) return '';
  return String(text)
    .replace(/\b(https?):\/\//gi, '$1[://]')
    .replace(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/g, '$1.$2.$3[.]$4');
}
