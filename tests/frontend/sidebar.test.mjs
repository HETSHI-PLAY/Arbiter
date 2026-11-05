import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const root = new URL('../../', import.meta.url);

test('sidebar state normalizes unknown values and toggles both directions', async () => {
  const {normalizeSidebarState, toggleSidebarState} = await import('../../app/static/js/state/sidebar.js');
  assert.equal(normalizeSidebarState('collapsed'), 'collapsed');
  assert.equal(normalizeSidebarState('expanded'), 'expanded');
  assert.equal(normalizeSidebarState(undefined), 'expanded');
  assert.equal(normalizeSidebarState('garbage'), 'expanded');
  assert.equal(toggleSidebarState('expanded'), 'collapsed');
  assert.equal(toggleSidebarState('collapsed'), 'expanded');
});

test('sidebar state persists to storage and survives storage failures', async () => {
  const {readSidebarState, writeSidebarState, SIDEBAR_KEY} = await import('../../app/static/js/state/sidebar.js');
  const data = new Map();
  const storage = {getItem: key => data.get(key) ?? null, setItem: (key, value) => data.set(key, value)};
  writeSidebarState(storage, 'collapsed');
  assert.equal(data.get(SIDEBAR_KEY), 'collapsed');
  assert.equal(readSidebarState(storage), 'collapsed');
  writeSidebarState(storage, 'unexpected');
  assert.equal(readSidebarState(storage), 'expanded');
  const broken = {getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); }};
  assert.equal(readSidebarState(broken), 'expanded');
  assert.doesNotThrow(() => writeSidebarState(broken, 'collapsed'));
  assert.equal(readSidebarState(null), 'expanded');
});

test('shell exposes a desktop sidebar toggle wired to collapse state', () => {
  const html = readFileSync(new URL('app/index.html', root), 'utf8');
  assert.match(html, /id="toggle-sidebar"[^>]*aria-controls="sidebar"[^>]*aria-expanded="true"/);
  assert.match(html, /id="toggle-sidebar"[^>]*aria-label="Sembunyikan navigasi"/);
  const css = readFileSync(new URL('app/static/styles/shell.css', root), 'utf8');
  assert.match(css, /@media\(min-width:1100px\)\{[^}]*\.sidebar-toggle\{display:inline-flex\}/);
  assert.match(css, /\.app-shell\.is-sidebar-collapsed\{grid-template-columns:minmax\(0,1fr\)\}/);
  assert.match(css, /\.app-shell\.is-sidebar-collapsed \.sidebar\{display:none\}/);
  const app = readFileSync(new URL('app/static/js/app.js', root), 'utf8');
  assert.match(app, /toggleSidebarState\(sidebarState\)/);
  assert.match(app, /is-sidebar-collapsed/);
});
