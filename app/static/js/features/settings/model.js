export const DEFAULT_SETTINGS = {
  wazuh: {
    enabled: false,
    indexer_url: '',
    username: '',
    index_pattern: 'wazuh-alerts-*',
    verify_tls: true,
    password_set: false,
    auth_configured: false,
  },
  realtime: {enabled: false, interval_seconds: 30, mode: 'interval', last_pull_at: '', max_alerts: 500},
  ai: {
    enabled: false,
    base_url: 'http://127.0.0.1:11434',
    model: 'hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M',
    timeout_seconds: 90,
  },
  ui: {sidebar_default: 'expanded'},
};

const clone = value => JSON.parse(JSON.stringify(value));

export function normalizeSettings(value) {
  const base = clone(DEFAULT_SETTINGS);
  if (!value || typeof value !== 'object') return base;
  for (const section of ['wazuh', 'realtime', 'ai', 'ui']) {
    if (value[section] && typeof value[section] === 'object') Object.assign(base[section], value[section]);
  }
  base.wazuh.enabled = Boolean(base.wazuh.enabled);
  base.wazuh.verify_tls = base.wazuh.verify_tls !== false;
  base.wazuh.password_set = Boolean(base.wazuh.password_set);
  base.realtime.enabled = Boolean(base.realtime.enabled);
  const interval = Number(base.realtime.interval_seconds);
  base.realtime.interval_seconds = Number.isFinite(interval) && interval >= 10 && interval <= 300 ? interval : 30;
  if (!['interval', 'daily'].includes(base.realtime.mode)) base.realtime.mode = 'interval';
  base.realtime.last_pull_at = String(base.realtime.last_pull_at || '');
  const maxAlerts = Number(base.realtime.max_alerts);
  base.realtime.max_alerts = Number.isFinite(maxAlerts) && maxAlerts >= 1 && maxAlerts <= 5000 ? maxAlerts : 500;
  base.ai.enabled = Boolean(base.ai.enabled);
  const aiTimeout = Number(base.ai.timeout_seconds);
  base.ai.timeout_seconds = Number.isFinite(aiTimeout) && aiTimeout >= 10 && aiTimeout <= 180 ? aiTimeout : 90;
  if (!['expanded', 'collapsed'].includes(base.ui.sidebar_default)) base.ui.sidebar_default = 'expanded';
  return base;
}

export function realtimeLabel(settings) {
  const normalized = normalizeSettings(settings);
  if (!normalized.realtime.enabled) return 'Monitor realtime: nonaktif';
  if (normalized.realtime.mode === 'daily') return 'Monitor realtime: pull harian (1× per 24 jam)';
  return `Monitor realtime: pull setiap ${normalized.realtime.interval_seconds} detik`;
}

export function wazuhSummary(settings) {
  const normalized = normalizeSettings(settings);
  const wazuh = normalized.wazuh;
  if (!wazuh.indexer_url) return 'Wazuh Indexer belum dikonfigurasi';
  if (!wazuh.enabled) return 'Wazuh Indexer dikonfigurasi, monitor dimatikan';
  return `Wazuh Indexer aktif · ${wazuh.index_pattern}`;
}

export function aiLabel(settings) {
  const normalized = normalizeSettings(settings);
  if (!normalized.ai.enabled) return 'AI Triage: nonaktif (heuristik lokal)';
  return `AI Triage: ${normalized.ai.model} via ${normalized.ai.base_url}`;
}
