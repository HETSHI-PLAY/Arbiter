import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root = new URL('../../', import.meta.url);

test('settings model normalizes partial payloads and enforces safe bounds', async () => {
  const {normalizeSettings, realtimeLabel, wazuhSummary} = await import('../../app/static/js/features/settings/model.js');
  const defaults = normalizeSettings(null);
  assert.equal(defaults.wazuh.index_pattern, 'wazuh-alerts-*');
  assert.equal(defaults.realtime.interval_seconds, 30);
  assert.equal(defaults.ui.sidebar_default, 'expanded');
  assert.equal(defaults.wazuh.verify_tls, true);

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
  assert.match(view, /rule\.level ≥ 7/);
  assert.match(view, /arbiter:settings-saved/);
  const router = readFileSync(new URL('app/static/js/router.js', root), 'utf8');
  assert.match(router, /'settings'/);
});

test('router resolves the settings destination and rejects unknown pages', async () => {
  const {parseRoute} = await import('../../app/static/js/router.js');
  assert.equal(parseRoute('#/settings?tenant=all').page, 'settings');
  assert.equal(parseRoute('#/settings-does-not-exist').page, 'not-found');
});
