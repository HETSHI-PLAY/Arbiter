import {choices, integer, queryFrom, scopeParams, tenantScope, tenantValues} from '../../state/scope.js';
import {withParams} from '../../router.js';

export function drilldownScrollBehavior(matchMedia = globalThis.matchMedia?.bind(globalThis)) {
  return matchMedia?.('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth';
}

export const PIVOT_OPTIONS = [
  ['rule_description', 'Deskripsi rule'],
  ['rule_id', 'Rule ID'],
  ['severity', 'Severity level'],
  ['source_ip', 'Source IP'],
  ['agent', 'Host / Agent'],
  ['http_status', 'HTTP status code'],
  ['http_method', 'HTTP Method'],
  ['url_path', 'URL / Path'],
  ['referer', 'HTTP Referer'],
  ['user_agent', 'User-Agent'],
  ['pattern', 'Pola teks tertentu'],
  ['tenant', 'Tenant'],
];

export const METRIC_OPTIONS = [
  ['alerts', 'Alert (Dedup)'],
  ['events', 'Event mentah'],
];

export const CHART_OPTIONS = [
  ['bar', 'Balok'],
  ['donut', 'Donut'],
  ['line', 'Tren waktu'],
  ['table', 'Tabel'],
];

export function normalizeStatsQuery(params = new URLSearchParams()) {
  const get = key => params instanceof URLSearchParams ? params.get(key) : params?.[key];
  const base = queryFrom(params);
  const pKeys = PIVOT_OPTIONS.map(([k]) => k);
  const pivot_by = choices(get('pivot_by'), pKeys, 'rule_description');
  const metric = choices(get('metric'), ['alerts', 'events'], 'alerts');
  const chart = choices(get('chart'), ['bar', 'donut', 'line', 'table'], 'bar');
  const chart_scale = choices(get('chart_scale'), ['normal', 'large'], 'normal');
  const top_n = Math.min(1000, Math.max(1, integer(get('top_n'), 500) || 500));
  const bucket = choices(get('bucket'), ['auto', 'minute', 'hour', 'day'], 'auto');
  const pattern = String(get('pattern') || '').trim();
  const secondary_pivot = choices(get('secondary_pivot'), pKeys.filter(k => k !== 'pattern'), '');
  const facet = String(get('facet') || '').trim();
  const facet_value = String(get('facet_value') || '').trim();
  const secondary_facet = String(get('secondary_facet') || '').trim();
  const secondary_facet_value = String(get('secondary_facet_value') || '').trim();

  return {
    ...base,
    pivot_by,
    secondary_pivot,
    metric,
    chart,
    chart_scale,
    top_n,
    bucket,
    pattern,
    facet,
    facet_value,
    secondary_facet,
    secondary_facet_value,
  };
}

export function distributionPercentages(items = [], otherCount = 0, total = 0) {
  if (!items.length && otherCount <= 0) return [];
  if (total <= 0) return items.map(it => ({...it, displayPercentage: 0}));

  const all = items.map(it => ({...it, displayPercentage: (it.count / total) * 100}));
  let sum = 0;
  const rounded = all.map(it => {
    const val = Math.round(it.displayPercentage * 10) / 10;
    sum += val;
    return {...it, displayPercentage: val};
  });

  const remainder = Math.round((100.0 - sum) * 10) / 10;
  if (remainder !== 0 && rounded.length > 0) {
    rounded[rounded.length - 1].displayPercentage = Math.round((rounded[rounded.length - 1].displayPercentage + remainder) * 10) / 10;
  }
  return rounded;
}

export function statsScopeParams(query) {
  const p = scopeParams(query);
  if (query.pivot_by && query.pivot_by !== 'rule_description') p.set('pivot_by', query.pivot_by);
  if (query.secondary_pivot) p.set('secondary_pivot', query.secondary_pivot);
  if (query.metric && query.metric !== 'alerts') p.set('metric', query.metric);
  if (query.chart && query.chart !== 'bar') p.set('chart', query.chart);
  if (query.chart_scale && query.chart_scale !== 'normal') p.set('chart_scale', query.chart_scale);
  if (query.top_n && query.top_n !== 500) p.set('top_n', String(query.top_n));
  if (query.bucket && query.bucket !== 'auto') p.set('bucket', query.bucket);
  if (query.pattern) p.set('pattern', query.pattern);
  if (query.facet) p.set('facet', query.facet);
  if (query.facet_value) p.set('facet_value', query.facet_value);
  if (query.secondary_facet) p.set('secondary_facet', query.secondary_facet);
  if (query.secondary_facet_value) p.set('secondary_facet_value', query.secondary_facet_value);
  return p;
}

export function triageRouteFromStats(query, {facet, facet_value, secondary_facet, secondary_facet_value} = {}) {
  const p = new URLSearchParams();
  for (const t of tenantValues(query)) p.append('tenant', t);
  if (query.q) p.set('q', query.q);
  if (query.filter_preset) p.set('filter_preset', query.filter_preset);
  if (query.status && query.status !== 'all') p.set('status', query.status);
  if (query.review_status && query.review_status !== 'unreviewed') p.set('review_status', query.review_status);
  if (query.time_preset) p.set('time_preset', query.time_preset);
  if (query.time_from) p.set('time_from', query.time_from);
  if (query.time_to) p.set('time_to', query.time_to);

  const f = facet || query.facet;
  const fv = facet_value || query.facet_value;
  if (f && fv) {
    p.set('facet', f);
    p.set('facet_value', fv);
  }
  const sf = secondary_facet || query.secondary_facet;
  const sfv = secondary_facet_value || query.secondary_facet_value;
  if (sf && sfv) {
    p.set('secondary_facet', sf);
    p.set('secondary_facet_value', sfv);
  }
  return withParams('/triage', p);
}

export function generateStatsCSV(data) {
  const lines = ['Kategori,Jumlah,Persen'];
  for (const it of (data.items || [])) {
    const key = String(it.key).replace(/"/g, '""');
    lines.push(`"${key}",${it.count},${it.displayPercentage ?? it.percentage}`);
  }
  if (data.other_count > 0) {
    lines.push(`"Lainnya",${data.other_count},${data.other_percentage}`);
  }
  return lines.join('\n');
}

export function generateMarkdownSummary(data) {
  const metricLabel = data.metric === 'events' ? 'event' : 'alert';
  const lines = [
    '### Ringkasan Statistik Alert',
    `- Acuan Pivot: ${data.pivot_by}`,
    `- Total: ${data.total} ${metricLabel}`,
    '- Top Kategori:',
  ];
  for (const it of (data.items || [])) {
    lines.push(`  - ${it.key}: ${it.count} (${it.displayPercentage ?? it.percentage}%)`);
  }
  if (data.other_count > 0) {
    lines.push(`  - Lainnya: ${data.other_count} (${data.other_percentage}%)`);
  }
  return lines.join('\n');
}

export const MALICIOUS_PATTERNS = [
  // 1. Secrets, keys, cloud credentials & environment
  /\.?_?env(\d*|ironment)?(\b|\.|\/|$)/i,
  /\.git(\b|\/|$)/i,
  /\.svn(\b|\/|$)/i,
  /\.ssh(\b|\/|$)/i,
  /id_rsa/i,
  /\.(npmrc|netrc|boto|htpasswd)\b/i,
  /client\.key/i,
  /(service-account|gcp-key|gcp-sa|gcloud|aws|env|firebase(-adminsdk)?)\.json/i,
  /auth\.json/i,
  /credentials?/i,
  /secret/i,
  /\.(aws|firebase)(\b|\/|$)/i,
  /(?:\.|%2e|%252e){2}(?:\/|\\|%2f|%5c)/i,
  /etc\/(passwd|shadow|hosts|issue|group)/i,
  /proc\/self/i,
  /(win|boot)\.ini/i,

  // 2. DevOps, CI/CD pipelines & container manifests
  /docker-compose(\..*)?\.ya?ml/i,
  /\.gitlab-ci(\..*)?\.ya?ml/i,
  /\.github\/(workflows|actions)/i,
  /bitbucket-pipelines\.ya?ml/i,

  // 3. Framework configs, backups & diagnostic files
  /appsettings(\..*)?\.json/i,
  /application(-.*)?\.(ya?ml|properties)/i,
  /(wp-)?config(\.php)?(\.bak|\.old|\.save|\.swp|\.orig)?(\b|$)/i,
  /configuration\.php/i,
  /web\.config/i,
  /\.htaccess/i,
  /backup(\b|\/|\.|$)/i,
  /\.(bak|old|save|swp|sql|tar|gz|zip|rar|7z)$/i,
  /(router|modem|gateway).*config/i,
  /(rom-0|config\.bin)/i,
  /(info|debug|test)\.php(\b|\?|$)/i,
  /phpinfo/i,
  /\.(js|png|jpg|gif|css|txt)\.php(\b|\?|$)/i, // double-extension webshell probe
  /\/icons\/.*(\.php|phpinfo|settings\.json)/i,

  // 4. JBoss, ColdFusion, PAN-OS, Aviatrix & Java/Server exploits
  /cms_changeDeviceContext/i,
  /\/avi\/avigui/i,
  /cache_template/i,
  /\.tpl\.php/i,
  /(jmx|web)-console/i,
  /jboss/i,
  /invoker/i,
  /coldfusion/i,
  /cfide/i,
  /uploadedfiles?/i,
  /filemanager/i,
  /\.(jsp|jspx|do|action)(\b|\?|$)/i,
  /struts/i,
  /solr/i,
  /actuator(\b|\/|$)/i,
  /\/geoserver/i,

  // 5. Router, IoT & Hardware gateway exploits
  /gpon(form)?/i,
  /diag_form/i,
  /boaform/i,
  /cobbler(_api)?/i,
  /hnap/i,
  /cgi-bin/i,
  /setup\.cgi/i,

  // 6. CMS, WordPress, REST API & Framework probe targets
  /xmlrpc(\.php)?/i,
  /wp-json(\/|$)/i,
  /rest_route=/i,
  /wp-(login|admin|content|includes)/i,
  /wlwmanifest/i,
  /admin(istrator)?(\b|\/|\.|$)/i,
  /setup(\.php)?/i,
  /install(\.php)?/i,
  /telescope/i,
  /graphql/i,
  /(swagger|api-docs)/i,

  // 7. Component, package & dependency disclosure
  /bower\.json/i,
  /package\.json/i,
  /composer\.(json|lock)/i,
  /jquery-file-upload/i,
  /vendor\/.*(phpunit|autoload)/i,

  // 8. Decentralized / Web3 abuse
  /\/ipfs\//i,

  // 9. Database administration tools & web shells
  /(db|database|websql|dbweb)(\/|$)/i,
  /phpmyadmin/i,
  /\bpma(\b|\/|$)/i,
  /adminer(\.php)?/i,
  /shell(\.php)?/i,
  /(wso|alfa|b374k|c99|r57)(\.php)?/i,
  /eval-stdin/i,
  /cmd(\.exe)?/i,
  /\b1337\b/,

  // 10. Dotfiles, root config files & random 404 fingerprinting probes
  /\/(\.(?!well-known[/?#]|$)[a-zA-Z0-9_.-]+)/i,
  /^\/[^/]+\.(json|ya?ml|cfg|properties|template|key|boto|htpasswd)(\?|$)/i,
  /^\/[a-zA-Z0-9_-]{10,}(\?|$)/i,
  /^\/index\.php\?(lang|id|file|page)=/i,
  /\/custom_403\.html/i,
];

export const BENIGN_WHITELIST_PATTERNS = [
  /^\/index\.php\/(sebatik|informatika|snsebatik2018|index)(\/|$)/i,
  /^\/plugins\/generic\/pdfJsViewer\//i,
  /^\/lib\/pkp\//i,
  /^\/\.well-known\//i,
  /^\/(sitemap\.xml|ads\.txt|robots\.txt|favicon\.ico)(\?|$)/i,
];

export const INJECTION_PATTERNS = [
  /(?:\.|%2e|%252e){2}(?:\/|\\|%2f|%5c)/i,
  /%22|%27|%3C|%3E|%7C|[\"'<>|]/,
  /rest_route=/i,
  /author=\d+/i,
  /phpinfo=/i,
];

export function isMaliciousPath(text = '') {
  const str = String(text || '').trim();
  if (!str) return false;
  let decoded = str;
  try {
    decoded = decodeURIComponent(str);
  } catch {
    // Keep raw if URI malformed
  }

  // 1. Parameter fuzzing & injection overrides whitelist
  if (INJECTION_PATTERNS.some(rx => rx.test(str) || rx.test(decoded))) {
    return true;
  }

  // 2. Legitimate OJS application paths whitelist guardrail
  if (BENIGN_WHITELIST_PATTERNS.some(rx => rx.test(str) || rx.test(decoded))) {
    return false;
  }

  // 3. Signature matching against malicious patterns
  return MALICIOUS_PATTERNS.some(rx => rx.test(str) || rx.test(decoded));
}

export function isMaliciousAlert(alert) {
  if (!alert) return false;
  const rawLog = alert.full_log || alert.raw?.full_log || (typeof alert.raw === 'string' ? alert.raw : '');
  let url = alert.data?.url || alert.data?.uri || alert.parsed_details?.path || alert.parsed_details?.uri || '';
  if ((!url || url === '/') && rawLog) {
    const m = rawLog.match(/\"(?:GET|POST|HEAD|PUT|DELETE)\s+([^\s]+)\s+HTTP\//i);
    if (m) url = m[1];
  }
  const method = String(alert.parsed_details?.method || (rawLog.match(/\"([A-Z]+)\s+[^\s]+\s+HTTP\//i)?.[1] || '')).toUpperCase();
  const ua = String(alert.parsed_details?.ua || alert.parsed_details?.user_agent || (rawLog.match(/\"([^\"]*)\"\s*$/)?.[1] || ''));

  // 1. Check suspicious method on unhandled endpoints
  if (method === 'POST' && (url === '/' || url === '/account' || url === '/index.php/sebatik' || url.startsWith('/avi/'))) {
    return true;
  }
  if (rawLog && /\"POST\s+(?:\/|\/(?:account|avi\/)[^\s]*|\/index\.php\/sebatik)\s+HTTP\//i.test(rawLog)) {
    return true;
  }

  // 2. Check scanner / anomalous User-Agent
  if (ua && /zgrab|Go Web Pentest Tool|masscan|nuclei|nikto|sqlmap|nmap|lkx-|traversalplugin|apache2449|leakix|Firefox\/3\.|Linux i686/i.test(ua)) {
    return true;
  }

  // 3. Check path and query payload on the extracted URI
  return isMaliciousPath(url);
}
