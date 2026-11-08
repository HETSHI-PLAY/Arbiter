export const VERDICT_META = {
  tp: {label: 'True Positive', badge: 'high', description: 'Indikasi aktivitas nyata yang perlu ditindaklanjuti.'},
  fp: {label: 'False Positive', badge: 'neutral', description: 'Aktivitas rutin atau administratif; tetap tinjau buktinya.'},
  needs_review: {label: 'Perlu ditinjau', badge: 'warning', description: 'Bukti belum cukup untuk memutuskan TP atau FP.'},
};

export const MODE_META = {
  local_ai: {label: 'AI lokal', badge: 'success'},
  local_rules: {label: 'Heuristik lokal', badge: 'neutral'},
  local_rules_fallback: {label: 'Fallback heuristik', badge: 'warning'},
};

export const MIN_LEVELS = [
  ['0-6', 'Low (rule.level 0–6)'],
  ['7-11', 'Medium (rule.level 7–11)'],
  ['12-14', 'High (rule.level 12–14)'],
  ['15', 'Critical (rule.level 15+)'],
];

export const MIN_LIMIT = 1;
export const MAX_LIMIT = 5000;
export const LIMITS = [10, 20, 40, 60, 100];

export const REVIEW_STATUSES = [
  ['unreviewed', 'Belum direview'],
  ['all', 'Semua status review'],
  ['reviewed', 'Sudah direview'],
];

export const GROUP_BY_OPTIONS = [
  ['rule_description', 'Rule description (per tenant)'],
  ['host_rule', 'Host / Agent + Rule'],
];

export function wibWindowKey(value) {
  if (!value) return '';
  let text = String(value).trim();
  if (!text) return '';
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) {
    text = `${text}T00:00:00+07:00`;
  } else {
    text = text.replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  }
  const ms = Date.parse(text);
  if (!Number.isFinite(ms)) return '';
  const wibDate = new Date(ms + 7 * 3600 * 1000);
  if (wibDate.getUTCHours() >= 17) {
    wibDate.setUTCDate(wibDate.getUTCDate() + 1);
  }
  const yyyy = wibDate.getUTCFullYear();
  const mm = String(wibDate.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(wibDate.getUTCDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}T17:00+07:00`;
}

export function formatWibWindowLabel(windowKey) {
  const text = String(windowKey || '').trim();
  if (text.length >= 16 && text.includes('T17:00')) {
    return `${text.slice(0, 10)} 17:00 WIB`;
  }
  return text;
}

export function aiSeverityKey(level) {
  const n = Number(level) || 0;
  if (n >= 15) return 'critical';
  if (n >= 12) return 'high';
  if (n >= 7) return 'medium';
  return 'low';
}

export function parseSeveritySelection(value) {
  const raw = String(value ?? '7-11').trim();
  if (raw === '0-6' || raw === '0') return {selection: '0-6', minRuleLevel: 0, maxRuleLevel: 6};
  if (raw === '7-11' || raw === '7' || raw === '') return {selection: '7-11', minRuleLevel: 7, maxRuleLevel: 11};
  if (raw === '12-14' || raw === '12') return {selection: '12-14', minRuleLevel: 12, maxRuleLevel: 14};
  if (raw === '15+' || raw === '15') return {selection: '15', minRuleLevel: 15, maxRuleLevel: null};
  const minRuleLevel = boundedInteger(raw, 7, 0, 16);
  return {selection: String(minRuleLevel), minRuleLevel, maxRuleLevel: null};
}

export function verdictMeta(value) {
  return VERDICT_META[value] || VERDICT_META.needs_review;
}

export function modeMeta(value) {
  return MODE_META[value] || {label: 'Mode tidak diketahui', badge: 'neutral'};
}

export function boundedInteger(value, fallback, min, max) {
  if (value === null || value === undefined || value === '') return fallback;
  const number = Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(number)));
}

export function triageOptions(params) {
  const get = key => params?.get ? params.get(key) : params?.[key];
  const limit = boundedInteger(get('limit'), 40, MIN_LIMIT, MAX_LIMIT);
  const rawLevel = get('min_rule_level');
  const rawMax = get('max_rule_level');
  const parsed = parseSeveritySelection(rawLevel);
  const maxRuleLevel = rawMax !== null && rawMax !== undefined && rawMax !== ''
    ? boundedInteger(rawMax, parsed.minRuleLevel, parsed.minRuleLevel, 16)
    : parsed.maxRuleLevel;
  const selection = maxRuleLevel === 6 && parsed.minRuleLevel === 0
    ? '0-6'
    : maxRuleLevel === 11 && parsed.minRuleLevel === 7
      ? '7-11'
      : maxRuleLevel === 14 && parsed.minRuleLevel === 12
        ? '12-14'
        : parsed.selection;
  const status = String(get('review_status') || 'unreviewed');
  const groupBy = String(get('group_by') || 'rule_description');
  return {
    limit,
    minRuleLevel: parsed.minRuleLevel,
    maxRuleLevel,
    severitySelection: selection,
    reviewStatus: REVIEW_STATUSES.some(([value]) => value === status) ? status : 'unreviewed',
    groupBy: GROUP_BY_OPTIONS.some(([value]) => value === groupBy) ? groupBy : 'rule_description',
  };
}

export function normalizeTriageResult(value) {
  const source = value && typeof value === 'object' ? value : {};
  const alerts = Array.isArray(source.alerts)
    ? source.alerts.filter(alert => alert && typeof alert === 'object' && alert.id !== undefined && alert.id !== null)
      .map(alert => ({...alert, id: String(alert.id), rule_level: Number(alert.rule_level) || 0}))
    : [];
  const byId = new Map(alerts.map(alert => [alert.id, alert]));
  const groups = [];
  if (Array.isArray(source.groups)) {
    for (const group of source.groups) {
      if (!group || typeof group !== 'object') continue;
      const ids = Array.isArray(group.alert_ids)
        ? [...new Set(group.alert_ids.map(String).filter(id => byId.has(id)))]
        : [];
      if (!ids.length) continue;
      const byBucket = new Map();
      const tenantsSeen = new Set();
      const windowsSeen = new Set();
      for (const id of ids) {
        const alert = byId.get(id);
        const alertTenant = String(alert?.tenant || group.tenant || '').trim();
        const winKey = String(wibWindowKey(alert?.timestamp) || group.window_key || '').trim();
        tenantsSeen.add(alertTenant);
        if (winKey) windowsSeen.add(winKey);
        const bucketKey = `${alertTenant}\u0000${winKey}`;
        if (!byBucket.has(bucketKey)) byBucket.set(bucketKey, {tenantName: alertTenant, winKey, bucketIds: []});
        byBucket.get(bucketKey).bucketIds.push(id);
      }
      const splitMultiTenant = tenantsSeen.size > 1;
      const splitMultiWindow = windowsSeen.size > 1;
      const rawNewIds = Array.isArray(group.new_alert_ids) ? new Set(group.new_alert_ids.map(String)) : new Set();
      for (const {tenantName, winKey, bucketIds} of byBucket.values()) {
        const baseTitle = String(group.title || 'Kelompok alert');
        let title = splitMultiTenant && tenantName && !baseTitle.startsWith(`[${tenantName}]`)
          ? `[${tenantName}] ${baseTitle}`
          : baseTitle;
        if (splitMultiWindow && winKey && !title.includes(formatWibWindowLabel(winKey))) {
          title = `${title} [≤ ${formatWibWindowLabel(winKey)}]`;
        }
        groups.push({
          tenant: tenantName,
          windowKey: winKey,
          groupKey: String(group.group_key || ''),
          savedGroupId: String(group.saved_group_id || ''),
          newAlertIds: bucketIds.filter(id => rawNewIds.has(id)),
          category: String(group.category || 'Tanpa kategori'),
          title,
          verdict: Object.hasOwn(VERDICT_META, group.verdict) ? group.verdict : 'needs_review',
          reason: String(group.reason || 'Tidak ada alasan yang disertakan.'),
          alertIds: bucketIds,
        });
      }
    }
  }
  const groupBy = GROUP_BY_OPTIONS.some(([mode]) => mode === source.group_by) ? source.group_by : 'host_rule';
  return {
    mode: typeof source.mode === 'string' ? source.mode : 'local_rules',
    warning: typeof source.warning === 'string' && source.warning ? source.warning : null,
    model: typeof source.model === 'string' ? source.model : '',
    alertCount: Number.isInteger(source.alert_count) ? source.alert_count : alerts.length,
    minRuleLevel: Number.isInteger(source.min_rule_level) ? source.min_rule_level : 7,
    maxRuleLevel: Number.isInteger(source.max_rule_level) ? source.max_rule_level : null,
    groupBy,
    savedAt: typeof source.saved_at === 'string' ? source.saved_at : '',
    windowKey: typeof source.window_key === 'string' ? source.window_key : '',
    alerts,
    groups,
  };
}

export function alertIndex(alerts) {
  return new Map(alerts.map(alert => [String(alert.id), alert]));
}

export function groupAlerts(group, index) {
  return (group.alertIds || []).map(id => index.get(String(id))).filter(Boolean);
}

export function summarizeGroups(groups) {
  const counts = {tp: 0, fp: 0, needs_review: 0};
  const ids = new Set();
  for (const group of groups) {
    counts[group.verdict] = (counts[group.verdict] || 0) + 1;
    for (const id of group.alertIds || []) ids.add(String(id));
  }
  return {...counts, groupCount: groups.length, alertCount: ids.size};
}

export function numericAlertIds(group, index) {
  return (group.alertIds || [])
    .map(String)
    .filter(id => index.has(id) && /^[1-9]\d*$/.test(id));
}

export function alertFacts(alert) {
  const facts = [];
  if (alert.tenant) facts.push(`Tenant ${alert.tenant}`);
  if (alert.agent_name) facts.push(`Agent ${alert.agent_name}`);
  if (alert.source_ip) facts.push(`Sumber ${alert.source_ip}`);
  if (alert.rule_id) facts.push(`Rule ${alert.rule_id}`);
  if (Number(alert.hit_count) > 1) facts.push(`${Number(alert.hit_count).toLocaleString('id-ID')} hits`);
  return facts;
}
