import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root = new URL('../../', import.meta.url);

test('settings model normalizes partial payloads and enforces safe bounds', async () => {
  const {
    REALTIME_SEVERITY_OPTIONS,
    normalizeSettings,
    parseRealtimeSeverity,
    realtimeLabel,
    realtimeSeverityLabel,
    realtimeSeveritySelection,
    wazuhSummary,
  } = await import('../../app/static/js/features/settings/model.js');
  const defaults = normalizeSettings(null);
  assert.equal(defaults.wazuh.index_pattern, 'wazuh-alerts-*');
  assert.equal(defaults.realtime.interval_seconds, 30);
  assert.equal(defaults.realtime.min_rule_level, 7);
  assert.equal(defaults.realtime.max_rule_level, null);
  assert.equal(defaults.ui.sidebar_default, 'expanded');
  assert.equal(defaults.wazuh.verify_tls, true);

  assert.deepEqual(
    REALTIME_SEVERITY_OPTIONS.map(([val]) => val),
    ['0-6', '7-11', '12-14', '15', '0'],
  );
  assert.deepEqual(parseRealtimeSeverity('0-6'), {selection: '0-6', min_rule_level: 0, max_rule_level: 6});
  assert.deepEqual(parseRealtimeSeverity('7-11'), {selection: '7-11', min_rule_level: 7, max_rule_level: 11});
  assert.deepEqual(parseRealtimeSeverity('12-14'), {selection: '12-14', min_rule_level: 12, max_rule_level: 14});
  assert.deepEqual(parseRealtimeSeverity('15'), {selection: '15', min_rule_level: 15, max_rule_level: null});
  assert.deepEqual(parseRealtimeSeverity('0'), {selection: '0', min_rule_level: 0, max_rule_level: null});
  assert.equal(realtimeSeveritySelection({min_rule_level: 12, max_rule_level: 14}), '12-14');
  assert.match(realtimeSeverityLabel({min_rule_level: 0, max_rule_level: 6}), /Low \(rule\.level 0–6\)/);

  const merged = normalizeSettings({wazuh: {indexer_url: 'https://wazuh.lab:9200', enabled: true}, realtime: {enabled: true, interval_seconds: 900}, ui: {sidebar_default: 'hidden'}});
  assert.equal(merged.wazuh.indexer_url, 'https://wazuh.lab:9200');
  assert.equal(merged.wazuh.enabled, true);
  assert.equal(merged.realtime.interval_seconds, 30, 'out-of-range interval falls back to 30');
  assert.equal(merged.ui.sidebar_default, 'expanded', 'unknown sidebar preference falls back');
  assert.match(realtimeLabel(merged), /pull setiap 30 detik/);
  assert.match(wazuhSummary(merged), /wazuh-alerts-\*/);

  assert.match(wazuhSummary(normalizeSettings(null)), /belum dikonfigurasi/i);
  assert.match(realtimeLabel(normalizeSettings(null)), /nonaktif/);
  // Daily mode labels distinctly from interval mode.
  assert.match(realtimeLabel({realtime: {enabled: true, mode: 'daily'}}), /24 jam/);
});

test('settings page exposes Wazuh Indexer credentials, realtime, and sidebar preference', () => {
  const html = readFileSync(new URL('app/index.html', root), 'utf8');
  assert.match(html, /data-page="settings" href="#\/settings"/);
  assert.match(html, /id="realtime-toggle"[^>]*aria-pressed="false"/);
  const view = readFileSync(new URL('app/static/js/features/settings/view.js', root), 'utf8');
  assert.match(view, /\/api\/settings\/wazuh\/test/);
  assert.match(view, /type="password"/);
  assert.match(view, /name="sidebar_default"/);
  assert.match(view, /name="interval_seconds"/);
  assert.match(view, /name="realtime_severity"/);
  assert.match(view, /rule\.level ≥ 7/);
  assert.match(view, /arbiter:settings-saved/);
  const router = readFileSync(new URL('app/static/js/router.js', root), 'utf8');
  assert.match(router, /'settings'/);
});

test('router resolves the settings and wazuh-queries destinations and rejects unknown pages', async () => {
  const {parseRoute} = await import('../../app/static/js/router.js');
  const {normalizeOllamaBaseUrl} = await import('../../app/static/js/features/settings/model.js');
  const {buildWazuhQueries} = await import('../../app/static/js/features/wazuh-queries/model.js');
  assert.equal(parseRoute('#/settings?tenant=all').page, 'settings');
  assert.equal(parseRoute('#/wazuh-queries?tenant=all').page, 'wazuh-queries');
  assert.equal(parseRoute('#/settings-does-not-exist').page, 'not-found');
  assert.equal(normalizeOllamaBaseUrl('http://192.168.30.178:11434/api/generate'), 'http://192.168.30.178:11434');
  const built = buildWazuhQueries({severity: '7-11', agent_name: 'web-01', keyword: '/etc/hosts'});
  assert.match(built.dql, /rule\.level >= 7 and rule\.level <= 11/);
  assert.match(built.dql, /agent\.name : "web-01"/);
  assert.match(built.dsl, /"rule\.level"/);
  assert.match(built.curl, /wazuh-alerts-\*/);
});
