import test from 'node:test';
import assert from 'node:assert/strict';
import {renderBarChart} from '../../app/static/js/ui/charts.js';
import {statsResults} from '../../app/static/js/features/stats/render.js';
import * as model from '../../app/static/js/features/stats/model.js';
const {normalizeStatsQuery} = model;

test('drilldown motion follows the user reduced-motion preference', () => {
  assert.equal(typeof model.drilldownScrollBehavior, 'function');
  assert.equal(model.drilldownScrollBehavior(() => ({matches:true})), 'instant');
  assert.equal(model.drilldownScrollBehavior(() => ({matches:false})), 'smooth');
});

test('stacked chart exposes every secondary legend category and keyboard target', () => {
  const categories = Array.from({length:12}, (_, i) => ({key:`Synthetic ${i}`,count:1}));
  const html = renderBarChart({items:[{key:'Rule',count:12}],total:12,secondaryDistribution:{Rule:categories}});
  assert.equal((html.match(/data-secondary-legend-key=/g)||[]).length,12);
  for (const cat of categories) assert.match(html,new RegExp(`data-secondary-key="${cat.key}"[^>]*tabindex="0"[^>]*role="button"`));
});

test('statistics tables are keyboard-scrollable and log expansion exposes its state', () => {
  const query = normalizeStatsQuery(new URLSearchParams('facet=rule_id&facet_value=42'));
  const html = statsResults({total:1,metric:'alerts',items:[{key:'42',count:1}]},query,{drilldownAlerts:[{id:1,description:'Synthetic'}]});
  assert.equal((html.match(/class="table-region" tabindex="0"/g)||[]).length,2);
  assert.match(html,/data-stats-action="toggle-log"[^>]*aria-expanded="false"/);
});

test('bar chart preserves readable category names without aggressive 20-char truncation', () => {
  const fullName = 'Synthetic application audit event'; // 33 chars
  const html = renderBarChart({items: [{key: fullName, count: 8}], total: 8});
  assert.match(html, new RegExp(fullName));
  assert.doesNotMatch(html, /Synthetic applicatio…/);
});

test('metric strip displays all tied top categories when multiple share the highest count', () => {
  const query = normalizeStatsQuery(new URLSearchParams(''));
  const items = [
    {key: 'Alpha Probe', count: 8},
    {key: 'Beta Scanner', count: 8},
    {key: 'Gamma Access', count: 5},
  ];
  const html = statsResults({total: 21, metric: 'alerts', items}, query);
  assert.match(html, /2 kategori seri/);
  assert.match(html, /Alpha Probe/);
  assert.match(html, /Beta Scanner/);
  assert.match(html, /masing-masing/);
});

test('secondary pivot universal top 10 limits to 10 by default with disclosure button when > 10 items', () => {
  const query = normalizeStatsQuery(new URLSearchParams('facet=rule_id&facet_value=5701&secondary_pivot=url_path'));
  // 15 items in random order with ties
  const breakdown = [
    {key: '/api/v1/user', count: 12},
    {key: '/admin/login', count: 25},
    {key: '/static/js/app.js', count: 8},
    {key: '/login', count: 25}, // tie with /admin/login -> /admin/login should come first alphabetically
    {key: '/health', count: 30},
    {key: '/api/docs', count: 5},
    {key: '/robots.txt', count: 2},
    {key: '/favicon.ico', count: 4},
    {key: '/api/v1/auth', count: 18},
    {key: '/portal', count: 7},
    {key: '/dashboard', count: 6},
    {key: '/logout', count: 3},
    {key: '/api/v1/alerts', count: 15},
    {key: '/export', count: 1},
    {key: '/backup.tar.gz', count: 1},
  ];
  const data = {
    total: 150,
    metric: 'alerts',
    pivot_by: 'rule_id',
    secondary_pivot: 'url_path',
    items: [{key: '5701', count: 150}],
    secondary_breakdown: breakdown,
  };

  // Default collapsed view: should only render 10 rows
  const collapsedHtml = statsResults(data, query, {showAllSecondary: false});
  const rowMatches = collapsedHtml.match(/<tr class="[^"]*">\s*<td style="width:40px;">/g) || [];
  assert.equal(rowMatches.length, 10, 'Must only render exactly 10 rows by default');
  assert.match(collapsedHtml, /data-stats-action="toggle-all-secondary"[^>]*aria-expanded="false"/);
  assert.match(collapsedHtml, /Tampilkan semua/);

  // Sorting check: highest count /health (30) must be first, then /admin/login (25) before /login (25)
  const healthIdx = collapsedHtml.indexOf('/health');
  const adminIdx = collapsedHtml.indexOf('/admin/login');
  const loginIdx = collapsedHtml.indexOf('/login');
  assert.ok(healthIdx !== -1 && adminIdx !== -1 && loginIdx !== -1);
  assert.ok(healthIdx < adminIdx, '/health (30) must come before /admin/login (25)');
  assert.ok(adminIdx < loginIdx, 'Tied items must sort alphabetically: /admin/login before /login');

  // 11th item (/api/docs with count 5 or /robots.txt with count 2) must NOT be in collapsed table
  assert.doesNotMatch(collapsedHtml, /data-select-secondary-key="\/robots\.txt"/);

  // Expanded view: should render all 15 rows
  const expandedHtml = statsResults(data, query, {showAllSecondary: true});
  const expandedRows = expandedHtml.match(/<tr class="[^"]*">\s*<td style="width:40px;">/g) || [];
  assert.equal(expandedRows.length, 15, 'Must render all 15 rows when expanded');
  assert.match(expandedHtml, /data-stats-action="toggle-all-secondary"[^>]*aria-expanded="true"/);
  assert.match(expandedHtml, /Tampilkan lebih sedikit/);
  assert.match(expandedHtml, /data-select-secondary-key="\/robots\.txt"/);
});

test('secondary pivot universal top 10 works on source_ip dimension and hides disclosure for <= 10 items', () => {
  const query = normalizeStatsQuery(new URLSearchParams('facet=rule_description&facet_value=SSH+Probe&secondary_pivot=source_ip'));
  // Exactly 10 items
  const tenBreakdown = Array.from({length: 10}, (_, i) => ({
    key: `192.168.1.${10 + i}`,
    count: 20 - i,
  }));
  const data10 = {
    total: 100,
    metric: 'alerts',
    pivot_by: 'rule_description',
    secondary_pivot: 'source_ip',
    items: [{key: 'SSH Probe', count: 100}],
    secondary_breakdown: tenBreakdown,
  };
  const html10 = statsResults(data10, query);
  assert.doesNotMatch(html10, /data-stats-action="toggle-all-secondary"/, 'Must not show disclosure button when exactly 10 items');

  // Less than 10 items (e.g. 4 items)
  const fourBreakdown = [
    {key: '10.0.0.1', count: 40},
    {key: '10.0.0.2', count: 30},
    {key: '10.0.0.3', count: 20},
    {key: '10.0.0.4', count: 10},
  ];
  const data4 = {
    total: 100,
    metric: 'alerts',
    pivot_by: 'rule_description',
    secondary_pivot: 'source_ip',
    items: [{key: 'SSH Probe', count: 100}],
    secondary_breakdown: fourBreakdown,
  };
  const html4 = statsResults(data4, query);
  assert.doesNotMatch(html4, /data-stats-action="toggle-all-secondary"/, 'Must not show disclosure button when < 10 items');
});

test('charts have enlarged visual dimensions for prominent desktop presentation', async () => {
  const {renderDonutChart, renderLineChart} = await import('../../app/static/js/ui/charts.js');
  // Bar chart viewBox width >= 900, rowHeight >= 44
  const barHtml = renderBarChart({items: [{key: 'Item 1', count: 10}], total: 10});
  assert.match(barHtml, /viewBox="0 0 ([9-9]\d{2}|[1-9]\d{3})/); // width >= 900

  // Donut chart enlarged (viewBox 380x380, rOuter >= 140)
  const donutHtml = renderDonutChart({items: [{key: 'Item 1', count: 10}], total: 10});
  assert.match(donutHtml, /viewBox="0 0 380 380"/);

  // Line chart enlarged (viewBox 840x320)
  const lineHtml = renderLineChart({timeSeries: [{bucket: '2026-01-01', total: 10}], topKeys: ['Item 1']});
  assert.match(lineHtml, /viewBox="0 0 840 320"/);
});

test('single subcategory drill-down mode is a distinct inspection level: filters to 1 row, omits top 10 toggle, and provides clear restore action', () => {
  const queryWithoutDrill = normalizeStatsQuery(new URLSearchParams('facet=rule_id&facet_value=5701&secondary_pivot=url_path'));
  const queryWithDrill = normalizeStatsQuery(new URLSearchParams('facet=rule_id&facet_value=5701&secondary_pivot=url_path&secondary_facet=url_path&secondary_facet_value=/admin/login'));

  const breakdown15 = Array.from({length: 15}, (_, i) => ({
    key: i === 0 ? '/admin/login' : `/path/${i}`,
    count: 30 - i,
  }));
  const data = {
    total: 300,
    metric: 'alerts',
    pivot_by: 'rule_id',
    secondary_pivot: 'url_path',
    items: [{key: '5701', count: 300}],
    secondary_breakdown: breakdown15,
  };

  // 1. In Level 1 (Pivot Kedua overview): Top 10 applies
  const overviewHtml = statsResults(data, queryWithoutDrill, {showAllSecondary: false});
  const overviewRows = overviewHtml.match(/<tr class="[^"]*">\s*<td style="width:40px;">/g) || [];
  assert.equal(overviewRows.length, 10, 'Overview must display Top 10 items');
  assert.match(overviewHtml, /data-stats-action="toggle-all-secondary"/, 'Overview must show Top 10 disclosure toggle');
  assert.doesNotMatch(overviewHtml, /id="btn-clear-secondary-drilldown"/, 'Overview must not have single drilldown clear button');

  // 2. In Level 2 (Single subcategory drill-down): Focused inspection applies
  const drilldownHtml = statsResults(data, queryWithDrill, {showAllSecondary: false});
  const drilldownRows = drilldownHtml.match(/<tr class="[^"]*">\s*<td style="width:40px;">/g) || [];
  assert.equal(drilldownRows.length, 1, 'Single subcategory drill-down must focus on exactly 1 row');
  assert.match(drilldownHtml, /\/admin\/login/);
  assert.doesNotMatch(drilldownHtml, /\/path\/1/);
  // Rule 8: <= 10 items must not show disclosure button
  assert.doesNotMatch(drilldownHtml, /data-stats-action="toggle-all-secondary"/, 'Single subcategory drill-down must omit Top 10 disclosure toggle');
  // Header provides explicit action to return to Level 1
  assert.match(drilldownHtml, /id="btn-clear-secondary-drilldown"/, 'Must provide clear restore button in header');
  assert.match(drilldownHtml, /Tampilkan Semua Sub-kategori \(15\)/);
});



