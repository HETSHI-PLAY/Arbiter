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
  [7, 'Medium+ (rule.level ≥ 7)'],
  [10, 'High+ (rule.level ≥ 10)'],
  [12, 'Critical (rule.level ≥ 12)'],
];

export const LIMITS = [10, 20, 40, 60, 100];

export const REVIEW_STATUSES = [
  ['unreviewed', 'Belum direview'],
  ['all', 'Semua status review'],
  ['reviewed', 'Sudah direview'],
];

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
  const limit = boundedInteger(get('limit'), 40, 5, 100);
  const minRuleLevel = boundedInteger(get('min_rule_level'), 7, 0, 15);
  const status = String(get('review_status') || 'unreviewed');
  return {
    limit,
    minRuleLevel,
    reviewStatus: REVIEW_STATUSES.some(([value]) => value === status) ? status : 'unreviewed',
  };
}

export function normalizeTriageResult(value) {
  const source = value && typeof value === 'object' ? value : {};
  const alerts = Array.isArray(source.alerts)
    ? source.alerts.filter(alert => alert && typeof alert === 'object' && alert.id !== undefined && alert.id !== null)
      .map(alert => ({...alert, id: String(alert.id), rule_level: Number(alert.rule_level) || 0}))
    : [];
  const validIds = new Set(alerts.map(alert => alert.id));
  const groups = Array.isArray(source.groups)
    ? source.groups.filter(group => group && typeof group === 'object').map(group => {
      const ids = Array.isArray(group.alert_ids)
        ? [...new Set(group.alert_ids.map(String).filter(id => validIds.has(id)))]
        : [];
      return {
        category: String(group.category || 'Tanpa kategori'),
        title: String(group.title || 'Kelompok alert'),
        verdict: Object.hasOwn(VERDICT_META, group.verdict) ? group.verdict : 'needs_review',
        reason: String(group.reason || 'Tidak ada alasan yang disertakan.'),
        alertIds: ids,
      };
    }).filter(group => group.alertIds.length)
    : [];
  return {
    mode: typeof source.mode === 'string' ? source.mode : 'local_rules',
    warning: typeof source.warning === 'string' && source.warning ? source.warning : null,
    model: typeof source.model === 'string' ? source.model : '',
    alertCount: Number.isInteger(source.alert_count) ? source.alert_count : alerts.length,
    minRuleLevel: Number.isInteger(source.min_rule_level) ? source.min_rule_level : 7,
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
  if (alert.agent_name) facts.push(`Agent ${alert.agent_name}`);
  if (alert.source_ip) facts.push(`Sumber ${alert.source_ip}`);
  if (alert.rule_id) facts.push(`Rule ${alert.rule_id}`);
  if (Number(alert.hit_count) > 1) facts.push(`${Number(alert.hit_count).toLocaleString('id-ID')} hits`);
  return facts;
}
