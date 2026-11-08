export const choices = (value, allowed, fallback) => allowed.includes(value) ? value : fallback;
export const integer = (value, fallback) => Number.isFinite(Number(value)) ? Math.floor(Number(value)) : fallback;

function rawTenantValues(params) {
  if (typeof params === 'string') return [params];
  if (Array.isArray(params)) return params;
  if (params instanceof URLSearchParams) return params.has('tenant') ? params.getAll('tenant') : ['all'];
  if (params && Array.isArray(params.tenants)) return params.tenants.length ? params.tenants : ['all'];
  if (params && Object.hasOwn(params, 'tenant')) return Array.isArray(params.tenant) ? params.tenant : [params.tenant];
  return ['all'];
}

export function tenantScope(params = new URLSearchParams()) {
  const raw = rawTenantValues(params).map(value => String(value ?? '').trim());
  if (raw.some(value => !value)) throw new Error('Tenant tidak boleh kosong. Pilih scope tenant kembali.');
  const unique = [...new Set(raw)].sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  if (unique.includes('all')) {
    if (unique.length !== 1) throw new Error('Semua tenant tidak dapat digabungkan dengan tenant bernama.');
    return {all: true, tenants: [], key: 'all', label: 'Semua tenant'};
  }
  const tenants = unique;
  return {all: false, tenants, key: JSON.stringify(tenants), label: tenants.length === 1 ? `Tenant ${tenants[0]}` : `${tenants.length} tenant`};
}

export function tenantValues(params = new URLSearchParams()) {
  const scope = tenantScope(params);
  return scope.all ? ['all'] : scope.tenants;
}

export function queryFrom(params = new URLSearchParams()) {
  const get = key => params instanceof URLSearchParams ? params.get(key) : params?.[key];
  const scope = tenantScope(params);
  return {
    tenant: scope.all ? 'all' : scope.tenants[0], tenants: scope.tenants, tenantScope: scope,
    q: get('q') || '',
    review_status: choices(get('review_status'), ['all', 'reviewed', 'unreviewed'], 'unreviewed'),
    filter_preset: choices(get('filter_preset'), ['', '403', '404', 'repeating', 'non_http', 'bot', 'curl'], ''),
    status: choices(get('status'), ['all', 'grouped', 'ungrouped'], 'all'),
    group_id: get('group_id') || '',
    alert_ids: get('alert_ids') || '',
    facet: get('facet') || '',
    facet_value: get('facet_value') || '',
    secondary_facet: get('secondary_facet') || '',
    secondary_facet_value: get('secondary_facet_value') || '',
    sort_by: choices(get('sort_by'), ['timestamp', 'severity', 'hits'], 'timestamp'),
    sort: choices(get('sort'), ['asc', 'desc'], 'desc'),
    time_from: get('time_from') || '',
    time_to: get('time_to') || '',
    time_preset: get('time_preset') || '',
    limit: Math.min(10000, Math.max(1, integer(get('limit'), 50) || 50)),
    offset: Math.max(0, integer(get('offset'), 0) || 0),
  };
}

export function scopeParams(query, {ids, groupId} = {}) {
  const normalized = queryFrom(query instanceof URLSearchParams ? query : query || {});
  const params = new URLSearchParams();
  for (const tenant of tenantValues(normalized)) params.append('tenant', tenant);
  for (const [key, value] of Object.entries(normalized)) {
    if (!['tenant', 'tenants', 'tenantScope', 'limit', 'offset'].includes(key) && value !== '') params.set(key, String(value));
  }
  if (groupId) {
    params.set('group_id', groupId);
    for (const key of ['q', 'filter_preset', 'status']) params.delete(key);
    params.set('review_status', 'all');
  }
  if (ids !== undefined) {
    if (!Array.isArray(ids) || !ids.length || ids.some(id => !(/^[1-9]\d*$/.test(String(id))))) throw new Error('Pilihan alert tidak valid. Pilih ulang sebelum mengekspor.');
    const clean = [...new Set(ids.map(Number))].filter(Number.isSafeInteger).filter(id => id > 0);
    if (clean.length !== new Set(ids.map(Number)).size) throw new Error('Pilihan alert tidak valid. Pilih ulang sebelum mengekspor.');
    for (const key of ['q', 'review_status', 'filter_preset', 'status', 'group_id']) params.delete(key);
    params.set('alert_ids', clean.join(','));
  }
  return params;
}

export function scopeDescription(params) {
  const p = params instanceof URLSearchParams ? params : scopeParams(params);
  const scope = tenantScope(p);
  const parts = [scope.label];
  if (p.get('alert_ids')) parts.push(`${p.get('alert_ids').split(',').length} alert terpilih`);
  else {
    if (p.get('group_id')) parts.push('Insiden terpilih');
    if (p.get('q')) parts.push(`Pencarian: ${p.get('q')}`);
    if (p.get('review_status') === 'unreviewed') parts.push('Belum direview');
    if (p.get('review_status') === 'reviewed') parts.push('Sudah direview');
    if (p.get('filter_preset')) parts.push(`Filter ${p.get('filter_preset')}`);
    if (p.get('status') === 'ungrouped') parts.push('Belum masuk insiden');
    if (p.get('status') === 'grouped') parts.push('Sudah masuk insiden');
    if (p.get('time_preset')) parts.push(`Waktu: ${p.get('time_preset')}`);
    else if (p.get('time_from') || p.get('time_to')) parts.push(`Waktu: ${p.get('time_from') || '—'} s/d ${p.get('time_to') || 'kini'}`);
  }
  return parts.join(' · ');
}
