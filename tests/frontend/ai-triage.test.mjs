import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root = new URL('../../', import.meta.url);

test('ai-triage model normalizes verdicts, modes, and bounded controls', async () => {
  const {
    verdictMeta, modeMeta, boundedInteger, triageOptions, normalizeTriageResult,
    summarizeGroups, alertIndex, groupAlerts, numericAlertIds, alertFacts,
  } = await import('../../app/static/js/features/ai-triage/model.js');

  assert.equal(verdictMeta('tp').label, 'True Positive');
  assert.equal(verdictMeta('garbage').label, 'Perlu ditinjau');
  assert.equal(modeMeta('local_rules_fallback').badge, 'warning');
  assert.equal(modeMeta('unknown').label, 'Mode tidak diketahui');

  assert.equal(boundedInteger('40', 40, 5, 100), 40);
  assert.equal(boundedInteger('1', 40, 5, 100), 5);
  assert.equal(boundedInteger('999', 40, 5, 100), 100);
  assert.equal(boundedInteger('x', 40, 5, 100), 40);

  const options = triageOptions(new URLSearchParams('limit=20&min_rule_level=10&review_status=all'));
  assert.equal(options.limit, 20);
  assert.equal(options.minRuleLevel, 10);
  assert.equal(options.reviewStatus, 'all');
  const defaults = triageOptions(new URLSearchParams(''));
  assert.equal(defaults.limit, 40);
  assert.equal(defaults.minRuleLevel, 7);
  assert.equal(defaults.reviewStatus, 'unreviewed');

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
  assert.match(view, /Siapkan insiden/);
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
