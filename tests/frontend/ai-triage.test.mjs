import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root = new URL('../../', import.meta.url);

test('ai-triage model normalizes verdicts, modes, and bounded controls', async () => {
  const {
    GROUP_BY_OPTIONS, MIN_LEVELS, aiSeverityKey, parseSeveritySelection,
    wibWindowKey, formatWibWindowLabel,
    verdictMeta, modeMeta, boundedInteger, triageOptions, normalizeTriageResult,
    summarizeGroups, alertIndex, groupAlerts, numericAlertIds, alertFacts,
  } = await import('../../app/static/js/features/ai-triage/model.js');

  assert.equal(aiSeverityKey(6), 'low');
  assert.equal(aiSeverityKey(7), 'medium');
  assert.equal(aiSeverityKey(11), 'medium');
  assert.equal(aiSeverityKey(12), 'high');
  assert.equal(aiSeverityKey(14), 'high');
  assert.equal(aiSeverityKey(15), 'critical');

  assert.deepEqual(parseSeveritySelection('0-6'), {selection: '0-6', minRuleLevel: 0, maxRuleLevel: 6});
  assert.deepEqual(parseSeveritySelection('7-11'), {selection: '7-11', minRuleLevel: 7, maxRuleLevel: 11});
  assert.deepEqual(parseSeveritySelection('12-14'), {selection: '12-14', minRuleLevel: 12, maxRuleLevel: 14});
  assert.deepEqual(parseSeveritySelection('15'), {selection: '15', minRuleLevel: 15, maxRuleLevel: null});
  assert.deepEqual(MIN_LEVELS, [
    ['0-6', 'Low (rule.level 0–6)'],
    ['7-11', 'Medium (rule.level 7–11)'],
    ['12-14', 'High (rule.level 12–14)'],
    ['15', 'Critical (rule.level 15+)'],
  ]);

  assert.equal(verdictMeta('tp').label, 'True Positive');
  assert.equal(verdictMeta('garbage').label, 'Perlu ditinjau');
  assert.equal(modeMeta('local_rules_fallback').badge, 'warning');
  assert.equal(modeMeta('unknown').label, 'Mode tidak diketahui');

  assert.equal(boundedInteger('40', 40, 5, 100), 40);
  assert.equal(boundedInteger('1', 40, 5, 100), 5);
  assert.equal(boundedInteger('999', 40, 5, 100), 100);
  assert.equal(boundedInteger('x', 40, 5, 100), 40);

  const options = triageOptions(new URLSearchParams('limit=20&min_rule_level=10&review_status=all&group_by=host_rule'));
  assert.equal(options.limit, 20);
  assert.equal(options.minRuleLevel, 10);
  assert.equal(options.reviewStatus, 'all');
  assert.equal(options.groupBy, 'host_rule');
  const defaults = triageOptions(new URLSearchParams(''));
  assert.equal(defaults.limit, 40);
  assert.equal(defaults.minRuleLevel, 7);
  assert.equal(defaults.reviewStatus, 'unreviewed');
  assert.equal(defaults.groupBy, 'rule_description');
  assert.deepEqual(GROUP_BY_OPTIONS, [
    ['rule_description', 'Rule description (per tenant)'],
    ['host_rule', 'Host / Agent + Rule'],
  ]);

  const result = normalizeTriageResult({
    mode: 'local_ai',
    model: 'hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M',
    alert_count: 2,
    min_rule_level: 7,
    alerts: [
      {id: '1', rule_level: 12, description: 'brute force', source_ip: '1.2.3.4', hit_count: 9},
      {id: '2', rule_level: 7, description: 'routine', agent_name: 'host-a', hit_count: 1},
    ],
    groups: [
      {verdict: 'tp', alert_ids: ['1', '1'], reason: 'scan', title: 'G1', category: 'C'},
      {verdict: 'nonsense', alert_ids: ['2'], reason: '', title: 'G2', category: ''},
      {verdict: 'fp', alert_ids: ['999'], reason: '', title: 'orphan', category: ''},
    ],
  });
  assert.equal(result.alertCount, 2);
  assert.equal(result.groups.length, 2, 'orphan alert_ids are dropped');
  assert.equal(result.groups[0].verdict, 'tp');
  assert.deepEqual(result.groups[0].alertIds, ['1'], 'duplicate ids collapse');
  assert.equal(result.groups[1].verdict, 'needs_review', 'unknown verdict normalizes');

  const index = alertIndex(result.alerts);
  assert.equal(index.get('1').description, 'brute force');
  const grouped = groupAlerts(result.groups[0], index);
  assert.equal(grouped[0].id, '1');

  const counts = summarizeGroups(result.groups);
  assert.equal(counts.tp, 1);
  assert.equal(counts.needs_review, 1);
  assert.equal(counts.alertCount, 2);

  assert.deepEqual(numericAlertIds(result.groups[0], index), ['1']);
  assert.deepEqual(numericAlertIds({alertIds: ['2']}, index), ['2']);
  assert.deepEqual(numericAlertIds({alertIds: ['nope']}, index), []);

  assert.ok(alertFacts(result.alerts[0]).some(f => f.includes('1.2.3.4')));
  assert.ok(alertFacts(result.alerts[0]).some(f => f.includes('9 hits')));

  // Multi-tenant group guard: even if an upstream response mixed two tenants in one group,
  // normalizeTriageResult splits them into separate single-tenant groups.
  const splitResult = normalizeTriageResult({
    mode: 'local_rules',
    group_by: 'rule_description',
    alerts: [
      {id: '10', tenant: 'Alpha', rule_level: 10, description: 'Same desc', agent_name: 'host-1'},
      {id: '11', tenant: 'Alpha', rule_level: 10, description: 'Same desc', agent_name: 'host-2'},
      {id: '12', tenant: 'Beta', rule_level: 10, description: 'Same desc', agent_name: 'host-1'},
    ],
    groups: [
      {verdict: 'tp', alert_ids: ['10', '11', '12'], reason: 'r', title: 'Same desc', category: 'Rule description (per tenant)'},
    ],
  });
  assert.equal(splitResult.groups.length, 2, '1 group must never contain 2 or more tenants');
  assert.deepEqual(splitResult.groups[0].alertIds, ['10', '11']);
  assert.equal(splitResult.groups[0].tenant, 'Alpha');
  assert.deepEqual(splitResult.groups[1].alertIds, ['12']);
  assert.equal(splitResult.groups[1].tenant, 'Beta');

  // 17:00 WIB boundary tests:
  assert.equal(wibWindowKey('2026-11-08T16:59:59+07:00'), '2026-11-08T17:00+07:00');
  assert.equal(wibWindowKey('2026-11-08T09:59:59Z'), '2026-11-08T17:00+07:00');
  assert.equal(wibWindowKey('2026-11-08T17:00:00+07:00'), '2026-11-09T17:00+07:00');
  assert.equal(wibWindowKey('2026-11-08T10:00:00Z'), '2026-11-09T17:00+07:00');
  assert.equal(formatWibWindowLabel('2026-11-08T17:00+07:00'), '2026-11-08 17:00 WIB');

  // Alerts before and after 17:00 WIB in the same tenant are split into separate window groups:
  const windowSplit = normalizeTriageResult({
    mode: 'local_rules',
    group_by: 'rule_description',
    alerts: [
      {id: '20', tenant: 'Alpha', timestamp: '2026-11-08T15:00:00+07:00', rule_level: 10, description: 'SSH brute force'},
      {id: '21', tenant: 'Alpha', timestamp: '2026-11-08T16:30:00+07:00', rule_level: 10, description: 'SSH brute force'},
      {id: '22', tenant: 'Alpha', timestamp: '2026-11-08T17:05:00+07:00', rule_level: 10, description: 'SSH brute force'},
    ],
    groups: [
      {verdict: 'tp', alert_ids: ['20', '21', '22'], reason: 'r', title: 'SSH brute force', category: 'Rule description'},
    ],
  });
  assert.equal(windowSplit.groups.length, 2, 'alerts crossing 17:00 WIB are separated into distinct groups');
  assert.deepEqual(windowSplit.groups[0].alertIds, ['20', '21']);
  assert.equal(windowSplit.groups[0].windowKey, '2026-11-08T17:00+07:00');
  assert.deepEqual(windowSplit.groups[1].alertIds, ['22']);
  assert.equal(windowSplit.groups[1].windowKey, '2026-11-09T17:00+07:00');
});

test('ai-triage page sends only sanitized fields and offers TP/FP actions', () => {
  const view = readFileSync(new URL('app/static/js/features/ai-triage/view.js', root), 'utf8');
  assert.match(view, /\/api\/ai\/triage/);
  assert.match(view, /min_rule_level/);
  assert.match(view, /review_status/);
  // The POST body carries only tenant + control knobs; no alert content is echoed back up.
  assert.match(view, /body: JSON\.stringify\(\{[^}]*tenant[^}]*limit[^}]*min_rule_level[^}]*review_status/s);
  assert.doesNotMatch(view, /body: JSON\.stringify\(\{[^}]*raw[^}]*\)/s);
  assert.doesNotMatch(view, /body: JSON\.stringify\(\{[^}]*full_log[^}]*\)/s);
  assert.doesNotMatch(view, /body: JSON\.stringify\(\{[^}]*parsed_details[^}]*\)/s);
  // TP/FP/needs-review badges.
  assert.match(view, /True Positive/);
  assert.match(view, /False Positive/);
  assert.match(view, /Perlu ditinjau/);
  // Buka di Triage + Siapkan insiden actions.
  assert.match(view, /Buka di Triage/);
  assert.match(view, /scopedRoute\('\/triage',\s*\{alert_ids:\s*incidentIds\.join\(','\),\s*review_status:\s*'all'/);
  assert.match(view, /Siapkan insiden/);
  // Persist to editable incidents.
  assert.match(view, /\/api\/ai\/triage\/save/);
  assert.match(view, /Simpan ke Insiden/);
  assert.match(view, /verdict: group\.verdict/);
  assert.match(view, /alert_ids: group\.alertIds/);
  // Fallback is clearly labelled, never presented as AI.
  assert.match(view, /local_rules_fallback/);
  assert.match(view, /heuristik/i);
});

test('ai-triage markup lives behind a dedicated route and sidebar link', () => {
  const router = readFileSync(new URL('app/static/js/router.js', root), 'utf8');
  assert.match(router, /'ai-triage'/);
  const html = readFileSync(new URL('app/index.html', root), 'utf8');
  assert.match(html, /data-page="ai-triage" href="#\/ai-triage"/);
  assert.match(html, /data-page="realtime" href="#\/realtime"/);
  // AI mode and Realtime are separate menus.
  assert.notEqual(html.indexOf('data-page="realtime"'), html.indexOf('data-page="ai-triage"'));
});
