import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root = new URL('../../', import.meta.url);

test('realtime settings normalize daily mode and max_alerts bounds', async () => {
  const {normalizeSettings, realtimeLabel} = await import('../../app/static/js/features/settings/model.js');
  const defaults = normalizeSettings(null);
  assert.equal(defaults.realtime.mode, 'interval');
  assert.equal(defaults.realtime.max_alerts, 500);
  assert.equal(defaults.realtime.last_pull_at, '');

  const merged = normalizeSettings({realtime: {mode: 'daily', max_alerts: 1, last_pull_at: '2026-01-01T00:00:00+00:00'}});
  assert.equal(merged.realtime.mode, 'daily');
  assert.equal(merged.realtime.max_alerts, 1);
  assert.equal(merged.realtime.last_pull_at, '2026-01-01T00:00:00+00:00');

  const bad = normalizeSettings({realtime: {mode: 'bogus', max_alerts: 999999}});
  assert.equal(bad.realtime.mode, 'interval', 'unknown mode falls back to interval');
  assert.equal(bad.realtime.max_alerts, 500, 'out-of-range max_alerts falls back to 500');

  assert.match(realtimeLabel({realtime: {enabled: true, mode: 'daily'}}), /24 jam/);
  assert.match(realtimeLabel({realtime: {enabled: true, mode: 'interval', interval_seconds: 30}}), /pull setiap 30 detik/);
});

test('realtime page pulls and ingests instead of only counting', () => {
  const view = readFileSync(new URL('app/static/js/features/realtime/view.js', root), 'utf8');
  assert.match(view, /\/api\/realtime\/pull/);
  assert.doesNotMatch(view, /\/api\/realtime\/count/);
  assert.match(view, /method: 'POST'/);
  assert.match(view, /inserted/);
  assert.match(view, /deduplicated/);
  assert.match(view, /status === 'skipped'/);
  assert.match(view, /mode === 'daily'/);
});

test('incidents render AI verdicts and source', () => {
  const render = readFileSync(new URL('app/static/js/features/incidents/render.js', root), 'utf8');
  assert.match(render, /verdictLabel/);
  assert.match(render, /verdictBadge/);
  assert.match(render, /source === 'ai'/);
  assert.match(render, /True Positive/);
  assert.match(render, /False Positive/);
  assert.match(render, /Perlu ditinjau/);
});
