export const REALTIME_SEVERITY_OPTIONS = [
  ['0-6', 'Low (rule.level 0–6)'],
  ['7-11', 'Medium (rule.level 7–11)'],
  ['12-14', 'High (rule.level 12–14)'],
  ['15', 'Critical (rule.level 15+)'],
  ['0', 'Semua severity (rule.level ≥ 0)'],
];

export function parseRealtimeSeverity(value) {
  const raw = String(value ?? '7-11').trim();
  if (raw === '0-6') return {selection: '0-6', min_rule_level: 0, max_rule_level: 6};
  if (raw === '7-11' || raw === '7' || raw === '') return {selection: '7-11', min_rule_level: 7, max_rule_level: 11};
  if (raw === '12-14' || raw === '12') return {selection: '12-14', min_rule_level: 12, max_rule_level: 14};
  if (raw === '15+' || raw === '15') return {selection: '15', min_rule_level: 15, max_rule_level: null};
  if (raw === '0' || raw === 'all') return {selection: '0', min_rule_level: 0, max_rule_level: null};
  return {selection: '7-11', min_rule_level: 7, max_rule_level: 11};
}

export function realtimeSeveritySelection(realtime = {}) {
  const min = Number.isFinite(Number(realtime?.min_rule_level)) ? Number(realtime.min_rule_level) : 7;
  const maxRaw = realtime?.max_rule_level;
  const max = maxRaw === null || maxRaw === undefined || maxRaw === '' ? null : Number(maxRaw);
  if (min === 0 && max === 6) return '0-6';
  if (min === 7 && (max === 11 || max === null)) return '7-11';
  if (min === 12 && (max === 14 || max === null)) return '12-14';
  if (min >= 15) return '15';
  if (min === 0 && max === null) return '0';
  return '7-11';
}

export function realtimeSeverityLabel(realtime = {}) {
  const sel = realtimeSeveritySelection(realtime);
  const found = REALTIME_SEVERITY_OPTIONS.find(([val]) => val === sel);
  return found ? found[1] : 'Medium (rule.level 7–11)';
}

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
  realtime: {
    enabled: false,
    interval_seconds: 30,
    mode: 'interval',
    last_pull_at: '',
    max_alerts: 500,
    min_rule_level: 7,
    max_rule_level: null,
  },
  ai: {
    enabled: false,
    base_url: 'http://127.0.0.1:11434',
    model: 'hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M',
    timeout_seconds: 90,
  },
  intel: {
    web_url: 'http://localhost:3001',
    abuseipdb_key_set: false,
  },
  ui: {sidebar_default: 'expanded'},
};

export function normalizeOllamaBaseUrl(value) {
  let raw = String(value ?? '').trim();
  if (!raw) return 'http://127.0.0.1:11434';
  for (const suffix of ['/api/generate', '/api/tags', '/api/chat', '/api/embeddings', '/api/embed', '/v1/chat/completions', '/v1']) {
    if (raw.toLowerCase().endsWith(suffix)) {
      raw = raw.slice(0, -suffix.length);
      break;
    }
  }
  return raw.replace(/\/+$/, '');
}

const clone = value => JSON.parse(JSON.stringify(value));

export function normalizeSettings(value) {
  const base = clone(DEFAULT_SETTINGS);
  if (!value || typeof value !== 'object') return base;
  for (const section of ['wazuh', 'realtime', 'ai', 'intel', 'ui']) {
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
  const minLevel = Number(base.realtime.min_rule_level);
  base.realtime.min_rule_level = Number.isFinite(minLevel) && minLevel >= 0 && minLevel <= 16 ? Math.trunc(minLevel) : 7;
  const maxLevelRaw = base.realtime.max_rule_level;
  if (maxLevelRaw === null || maxLevelRaw === undefined || maxLevelRaw === '') {
    base.realtime.max_rule_level = null;
  } else {
    const maxLevel = Number(maxLevelRaw);
    base.realtime.max_rule_level = Number.isFinite(maxLevel) && maxLevel >= base.realtime.min_rule_level && maxLevel <= 16
      ? Math.trunc(maxLevel)
      : null;
  }
  base.ai.enabled = Boolean(base.ai.enabled);
  base.ai.base_url = normalizeOllamaBaseUrl(base.ai.base_url);
  const aiTimeout = Number(base.ai.timeout_seconds);
  base.ai.timeout_seconds = Number.isFinite(aiTimeout) && aiTimeout >= 10 && aiTimeout <= 180 ? aiTimeout : 90;
  const rawWebUrl = String(base.intel.web_url || '').trim().replace(/\/ip\/?$/i, '').replace(/\/+$/, '');
  base.intel.web_url = rawWebUrl || 'http://localhost:3001';
  base.intel.abuseipdb_key_set = Boolean(base.intel.abuseipdb_key_set);
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
