export const QUERY_SEVERITY_OPTIONS = [
  ['all', 'Semua severity (rule.level ≥ 0)'],
  ['0-6', 'Low (rule.level 0–6)'],
  ['7-11', 'Medium (rule.level 7–11)'],
  ['12-14', 'High (rule.level 12–14)'],
  ['15', 'Critical (rule.level 15+)'],
];

export const QUERY_TIME_OPTIONS = [
  ['now-1h', '1 jam terakhir (now-1h)'],
  ['now-6h', '6 jam terakhir (now-6h)'],
  ['now-24h', '24 jam terakhir (now-24h)'],
  ['now-7d', '7 hari terakhir (now-7d)'],
  ['now-30d', '30 hari terakhir (now-30d)'],
  ['', 'Tanpa filter waktu'],
];

export const PRESET_CATEGORIES = [
  'Semua',
  'Severity',
  'Web Exploit',
  'Autentikasi',
  'Filter Noise',
  'Endpoint & CVE',
];

export const PRESET_WAZUH_QUERIES = [
  {
    id: 'preset-sev-low',
    title: 'Filter Alert Severity Low (Level 0–6)',
    category: 'Severity',
    description: 'Menampilkan seluruh alert Wazuh dengan tingkat keparahan Low (rule.level 0 hingga 6).',
    dql: 'rule.level >= 0 and rule.level <= 6',
    lucene: 'rule.level:[0 TO 6]',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {range: {'rule.level': {gte: 0, lte: 6}}},
    }, null, 2),
    builderDefaults: {severity: '0-6'},
  },
  {
    id: 'preset-sev-medium',
    title: 'Filter Alert Severity Medium (Level 7–11)',
    category: 'Severity',
    description: 'Menampilkan alert Wazuh kategori Medium (rule.level 7 hingga 11) untuk triage operasional harian.',
    dql: 'rule.level >= 7 and rule.level <= 11',
    lucene: 'rule.level:[7 TO 11]',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {range: {'rule.level': {gte: 7, lte: 11}}},
    }, null, 2),
    builderDefaults: {severity: '7-11'},
  },
  {
    id: 'preset-sev-high',
    title: 'Filter Alert Severity High (Level 12–14)',
    category: 'Severity',
    description: 'Menampilkan alert Wazuh kategori High (rule.level 12 hingga 14) yang membutuhkan investigasi segera.',
    dql: 'rule.level >= 12 and rule.level <= 14',
    lucene: 'rule.level:[12 TO 14]',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {range: {'rule.level': {gte: 12, lte: 14}}},
    }, null, 2),
    builderDefaults: {severity: '12-14'},
  },
  {
    id: 'preset-sev-critical',
    title: 'Filter Alert Severity Critical (Level 15+)',
    category: 'Severity',
    description: 'Menampilkan alert kritis (rule.level ≥ 15) dengan prioritas eskalasi insiden tertinggi.',
    dql: 'rule.level >= 15',
    lucene: 'rule.level:[15 TO *]',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {range: {'rule.level': {gte: 15}}},
    }, null, 2),
    builderDefaults: {severity: '15'},
  },
  {
    id: 'preset-web-traversal',
    title: 'Deteksi Path Traversal, CGI & LFI (/etc/passwd, /etc/hosts, .%2e)',
    category: 'Web Exploit',
    description: 'Mendeteksi eksploitasi Apache/Nginx/CGI Path Traversal (.%2e, %2e%2e, ../, /cgi-bin/, /etc/passwd, /etc/hosts) meskipun merespons HTTP 400/403/404.',
    dql: '(full_log : "*.%2e*" or full_log : "*%2e%2e*" or full_log : "*../*" or full_log : "*/cgi-bin/*" or full_log : "*/etc/passwd*" or full_log : "*/etc/hosts*")',
    lucene: 'full_log:(*.%2e* OR *%2e%2e* OR *../* OR *\\/cgi-bin\\/* OR *\\/etc\\/passwd* OR *\\/etc\\/hosts*)',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {
        bool: {
          should: [
            {wildcard: {full_log: {value: '*.%2e*', case_insensitive: true}}},
            {wildcard: {full_log: {value: '*%2e%2e*', case_insensitive: true}}},
            {wildcard: {full_log: {value: '*../*', case_insensitive: true}}},
            {wildcard: {full_log: {value: '*/cgi-bin/*', case_insensitive: true}}},
            {wildcard: {full_log: {value: '*/etc/passwd*', case_insensitive: true}}},
            {wildcard: {full_log: {value: '*/etc/hosts*', case_insensitive: true}}},
          ],
          minimum_should_match: 1,
        },
      },
    }, null, 2),
    builderDefaults: {severity: 'all', searchKeyword: '/cgi-bin/'},
  },
  {
    id: 'preset-web-scanner',
    title: 'Deteksi Scanner Eksploitasi (LeakIX, Nuclei, SQLMap, Nikto, ZGrab)',
    category: 'Web Exploit',
    description: 'Mencari aktivitas pemindaian kerentanan otomatis berdasarkan jejak User-Agent atau payload scanner di full_log.',
    dql: '(full_log : "*LeakIX*" or full_log : "*TraversalPlugin*" or full_log : "*nuclei*" or full_log : "*sqlmap*" or full_log : "*nikto*" or full_log : "*zgrab*" or full_log : "*masscan*")',
    lucene: 'full_log:(*LeakIX* OR *TraversalPlugin* OR *nuclei* OR *sqlmap* OR *nikto* OR *zgrab* OR *masscan*)',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {
        query_string: {
          fields: ['full_log', 'data.url', 'rule.description'],
          query: '*LeakIX* OR *TraversalPlugin* OR *nuclei* OR *sqlmap* OR *nikto* OR *zgrab* OR *masscan*',
        },
      },
    }, null, 2),
    builderDefaults: {severity: 'all', searchKeyword: 'LeakIX'},
  },
  {
    id: 'preset-auth-bruteforce',
    title: 'Brute Force SSH & Kegagalan Autentikasi (Rule 5710, 5712, 5503)',
    category: 'Autentikasi',
    description: 'Menyaring percobaan login gagal berulang, user tidak dikenal, dan serangan brute-force SSH/PAM.',
    dql: 'rule.groups : "authentication_failed" or rule.groups : "authentication_failures" or rule.id : ("5710" or "5712" or "5503" or "5760")',
    lucene: 'rule.groups:(authentication_failed OR authentication_failures) OR rule.id:(5710 OR 5712 OR 5503 OR 5760)',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {
        bool: {
          should: [
            {terms: {'rule.groups': ['authentication_failed', 'authentication_failures']}},
            {terms: {'rule.id': ['5710', '5712', '5503', '5760']}},
          ],
          minimum_should_match: 1,
        },
      },
    }, null, 2),
    builderDefaults: {severity: '7-11', ruleIds: '5710, 5712, 5503, 5760'},
  },
  {
    id: 'preset-exclude-ar',
    title: 'Alert Medium+ Tanpa Noise Active Response (Rule 651 / 652)',
    category: 'Filter Noise',
    description: 'Menyaring alert Medium ke atas sembari mengecualikan log respons blokir otomatis (firewall-drop / host-deny) agar antrean tetap fokus pada serangan asal.',
    dql: 'rule.level >= 7 and not rule.id : ("651" or "652") and not rule.groups : "active_response"',
    lucene: 'rule.level:[7 TO *] AND NOT rule.id:(651 OR 652) AND NOT rule.groups:active_response',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {
        bool: {
          must: [{range: {'rule.level': {gte: 7}}}],
          must_not: [
            {terms: {'rule.id': ['651', '652']}},
            {term: {'rule.groups': 'active_response'}},
          ],
        },
      },
    }, null, 2),
    builderDefaults: {severity: '7-11', excludeNoise: true},
  },
  {
    id: 'preset-fim-syscheck',
    title: 'Perubahan File Penting (FIM / Syscheck & Rootcheck)',
    category: 'Endpoint & CVE',
    description: 'Memantau modifikasi, penambahan, atau penghapusan file sistem sensitif pada host yang dipantau.',
    dql: 'rule.groups : ("syscheck" or "syscheck_entry_modified" or "syscheck_entry_added" or "rootcheck") and rule.level >= 7',
    lucene: 'rule.groups:(syscheck OR syscheck_entry_modified OR syscheck_entry_added OR rootcheck) AND rule.level:[7 TO *]',
    dsl: JSON.stringify({
      size: 500,
      sort: [{timestamp: {order: 'desc'}}],
      query: {
        bool: {
          must: [
            {terms: {'rule.groups': ['syscheck', 'syscheck_entry_modified', 'syscheck_entry_added', 'rootcheck']}},
            {range: {'rule.level': {gte: 7}}},
          ],
        },
      },
    }, null, 2),
    builderDefaults: {severity: '7-11', searchKeyword: 'syscheck'},
  },
];

function parseSeverityBounds(severity) {
  const raw = String(severity || '7-11').trim();
  if (raw === '0-6') return {gte: 0, lte: 6};
  if (raw === '7-11') return {gte: 7, lte: 11};
  if (raw === '12-14') return {gte: 12, lte: 14};
  if (raw === '15') return {gte: 15, lte: null};
  return {gte: 0, lte: null};
}

export function buildWazuhQueries(params = {}) {
  const tenant = String(params.tenant || '').trim();
  const severity = String(params.severity || '7-11').trim();
  const agentName = String(params.agentName || params.agent_name || params.agent || '').trim();
  const sourceIp = String(params.sourceIp || params.source_ip || params.src_ip || '').trim();
  const ruleIdsRaw = String(params.ruleIds || params.rule_ids || params.rule_id || '').trim();
  const searchKeyword = String(params.searchKeyword || params.keyword || '').trim();
  const excludeNoise = Boolean(params.excludeNoise);
  const timeRange = String(params.timeRange ?? 'now-24h').trim();
  const size = Math.min(5000, Math.max(1, Number(params.size) || 500));

  const bounds = parseSeverityBounds(severity);
  const dqlParts = [];
  const luceneParts = [];
  const must = [];
  const mustNot = [];

  if (bounds.lte !== null) {
    dqlParts.push(`rule.level >= ${bounds.gte} and rule.level <= ${bounds.lte}`);
    luceneParts.push(`rule.level:[${bounds.gte} TO ${bounds.lte}]`);
    must.push({range: {'rule.level': {gte: bounds.gte, lte: bounds.lte}}});
  } else if (bounds.gte > 0) {
    dqlParts.push(`rule.level >= ${bounds.gte}`);
    luceneParts.push(`rule.level:[${bounds.gte} TO *]`);
    must.push({range: {'rule.level': {gte: bounds.gte}}});
  } else {
    dqlParts.push('rule.level >= 0');
    luceneParts.push('rule.level:[0 TO *]');
    must.push({range: {'rule.level': {gte: 0}}});
  }

  if (tenant && tenant !== 'all') {
    const safeTenant = tenant.replace(/"/g, '\\"');
    dqlParts.push(`agent.labels.tenant : "${safeTenant}"`);
    luceneParts.push(`agent.labels.tenant:"${safeTenant}"`);
    must.push({term: {'agent.labels.tenant': tenant}});
  }

  if (agentName) {
    const safeAgent = agentName.replace(/"/g, '\\"');
    dqlParts.push(`agent.name : "${safeAgent}"`);
    luceneParts.push(`agent.name:"${safeAgent}"`);
    must.push({term: {'agent.name': agentName}});
  }

  if (sourceIp) {
    const safeIp = sourceIp.replace(/"/g, '\\"');
    dqlParts.push(`data.srcip : "${safeIp}"`);
    luceneParts.push(`data.srcip:"${safeIp}"`);
    must.push({term: {'data.srcip': sourceIp}});
  }

  const ruleIds = ruleIdsRaw
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
  if (ruleIds.length === 1) {
    const r = ruleIds[0].replace(/"/g, '\\"');
    dqlParts.push(`rule.id : "${r}"`);
    luceneParts.push(`rule.id:"${r}"`);
    must.push({term: {'rule.id': ruleIds[0]}});
  } else if (ruleIds.length > 1) {
    const dqlList = ruleIds.map(r => `"${r.replace(/"/g, '\\"')}"`).join(' or ');
    const luceneList = ruleIds.map(r => `"${r.replace(/"/g, '\\"')}"`).join(' OR ');
    dqlParts.push(`rule.id : (${dqlList})`);
    luceneParts.push(`rule.id:(${luceneList})`);
    must.push({terms: {'rule.id': ruleIds}});
  }

  if (searchKeyword) {
    const safeKw = searchKeyword.replace(/"/g, '\\"');
    dqlParts.push(`(full_log : "*${safeKw}*" or rule.description : "*${safeKw}*")`);
    luceneParts.push(`(full_log:*${safeKw}* OR rule.description:*${safeKw}*)`);
    must.push({
      query_string: {
        fields: ['full_log', 'rule.description', 'data.url'],
        query: `*${searchKeyword}*`,
      },
    });
  }

  if (timeRange) {
    must.push({range: {timestamp: {gte: timeRange}}});
  }

  if (excludeNoise) {
    dqlParts.push('not rule.id : ("651" or "652") and not rule.groups : "active_response"');
    luceneParts.push('NOT rule.id:(651 OR 652) AND NOT rule.groups:active_response');
    mustNot.push({terms: {'rule.id': ['651', '652']}});
    mustNot.push({term: {'rule.groups': 'active_response'}});
  }

  const boolQuery = {must};
  if (mustNot.length) boolQuery.must_not = mustNot;

  const dslObject = {
    size,
    sort: [{timestamp: {order: 'desc'}}],
    query: {bool: boolQuery},
  };
  const dsl = JSON.stringify(dslObject, null, 2);
  const dslCompact = JSON.stringify(dslObject).replace(/'/g, "'\\''");
  const curl = `curl -k -u "<USERNAME>:<PASSWORD>" -X POST "https://<WAZUH_INDEXER_HOST>:9200/wazuh-alerts-*/_search" \\\n  -H "Content-Type: application/json" \\\n  -d '${dslCompact}'`;

  return {
    dql: dqlParts.join(' and '),
    lucene: luceneParts.join(' AND '),
    dsl,
    curl,
  };
}
