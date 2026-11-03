import test from 'node:test';
import assert from 'node:assert/strict';
import {renderTriageSummary, renderQueue, summaryRequestParams} from '../../app/static/js/features/triage/model.js';
import {queryFrom} from '../../app/static/js/state/scope.js';
import {statsPage} from '../../app/static/js/features/stats/render.js';
import {normalizeStatsQuery} from '../../app/static/js/features/stats/model.js';

const data = {
  alerts: 47, events: 1856, unique_source_ips: 47, unique_agents: 4,
  incident_cases: 2, severity: {critical: 11, high: 12, medium: 12, low: 12},
  time_range: {}, top_rule: {rule_id: '5', description: 'Synthetic rule', count: 8}
};

// === P0 REGRESSION: scope forwarding ===

test('P0: review_status=all is always forwarded to summaryRequestParams', () => {
  for (const status of ['all', 'reviewed', 'unreviewed']) {
    const q = queryFrom(new URLSearchParams(`review_status=${status}`));
    const params = summaryRequestParams(q);
    assert.equal(params.get('review_status'), status,
      `Expected review_status=${status} but got ${params.get('review_status')}`);
  }
});

test('P0: default queryFrom produces unreviewed, not null', () => {
  const q = queryFrom();
  assert.equal(q.review_status, 'unreviewed');
});

test('P0: summary count equals data.alerts in rendered output', () => {
  const html = renderTriageSummary(data, queryFrom());
  // 47 should appear as "47" in the summary
  assert.match(html, /47/, 'Expected alert count 47 in summary');
  // events 1856 formatted as 1.856 (id-ID locale)
  assert.match(html, /1\.856/, 'Expected event count 1.856 in summary');
});

// === EVIDENCE LEDGER: progressive disclosure ===

test('summary labels severity and preserves every pivot in progressive disclosure', () => {
  const html = renderTriageSummary(data, queryFrom());
  for (const name of ['Critical', 'High', 'Medium', 'Low']) {
    assert.match(html, new RegExp(`>${name} `), `Missing severity label ${name}`);
  }
  for (const action of ['pivot-ip', 'pivot-agent', 'severity', 'grouped', 'top-rule']) {
    assert.ok(html.includes(`data-summary-action="${action}"`), `Missing action ${action}`);
  }
  assert.ok(html.includes('<details class="summary-details"'), 'Missing progressive disclosure <details>');
  assert.match(html, /Lihat statistik lengkap/, 'Missing stats link');
  assert.match(html, /Belum direview/, 'Missing review status label');
});

test('summary collapsed mode hides details but keeps count and toggle', () => {
  const html = renderTriageSummary(data, queryFrom(), {collapsed: true});
  assert.ok(html.includes('is-collapsed'), 'Missing collapsed class');
  assert.ok(!html.includes('<details'), 'Details should not be rendered when collapsed');
  assert.match(html, /47/, 'Count should still appear in collapsed mode');
  assert.ok(html.includes('data-action="toggle-summary"'), 'Toggle button should still exist');
  assert.ok(html.includes('aria-expanded="false"'), 'aria-expanded should be false when collapsed');
});

test('summary without data returns empty string', () => {
  assert.equal(renderTriageSummary(null, queryFrom()), '');
});

test('summary review_status labels are correct for each scope', () => {
  const cases = [
    ['unreviewed', 'Belum direview'],
    ['reviewed', 'Direview'],
    ['all', 'Semua review'],
  ];
  for (const [status, expected] of cases) {
    const q = queryFrom(new URLSearchParams(`review_status=${status}`));
    const html = renderTriageSummary(data, q);
    assert.match(html, new RegExp(expected), `Expected label "${expected}" for status=${status}`);
  }
});

// === EVIDENCE LEDGER: Statistics ===

test('Statistics retains controls and actions with advanced disclosure and chart toolbar', () => {
  const html = statsPage(normalizeStatsQuery());
  assert.ok(html.includes('<details class="stats-advanced"'), 'Missing stats advanced disclosure');
  assert.ok(html.includes('class="stats-chart-toolbar"'), 'Missing chart toolbar');
  for (const id of ['stats-pivot', 'stats-secondary-pivot', 'stats-time', 'stats-metric-segmented',
    'stats-chart-segmented', 'stats-top-n', 'stats-preset-select', 'stats-custom-time-wrap',
    'stats-pattern-input', 'stats-results']) {
    assert.equal(html.split(`id="${id}"`).length, 2, `Expected exactly one #${id}`);
  }
  for (const action of ['export-csv', 'export-svg', 'copy-summary', 'reset-stats']) {
    assert.ok(html.includes(`data-action="${action}"`), `Missing action ${action}`);
  }
});

// === EVIDENCE LEDGER: queue log parity ===

test('expanded log actions have desktop/mobile parity and accessible disclosure state', () => {
  const html = renderQueue(
    [{id: 1, rule_level: 7, full_log: 'synthetic', description: 'Synthetic'}],
    {query: queryFrom(), showAllLogs: true}
  );
  // Defang button should appear in both desktop and mobile = 2 occurrences in full html
  // Desktop has it in log-expansion-row, mobile in queue-log-box
  assert.equal(html.split('data-action="copy-queue-defanged"').length, 3,
    'Expected defang action in both desktop and mobile expanded logs');
  assert.match(html, /aria-expanded="true"/, 'Missing aria-expanded on log toggle');
});

test('queue row renders correct aria-selected and inspected class', () => {
  const html = renderQueue(
    [{id: 42, rule_level: 3, description: 'Test'}],
    {query: queryFrom(), selectedIds: [42], activeId: 42}
  );
  assert.match(html, /aria-selected="true"/, 'Expected aria-selected=true for selected row');
  assert.match(html, /class="inspected"/, 'Expected inspected class for active row');
});

test('queue without intel column omits source column', () => {
  const html = renderQueue(
    [{id: 1, rule_level: 5, description: 'Test'}],
    {query: queryFrom(), showIntel: false}
  );
  assert.ok(!html.includes('Source / intel'), 'Intel column header should be absent');
  assert.ok(!html.includes('source-col'), 'source-col class should be absent');
});
