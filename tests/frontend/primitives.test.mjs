import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
const url = new URL('../../app/static/js/ui/primitives.js', import.meta.url);
test('UI primitives escape data, bound icons and express severity without color alone', async () => {
  assert.ok(existsSync(url), 'UI primitives must exist');
  const {esc, icon, severity, statusLabel} = await import(url);
  assert.equal(esc('<script>"&'), '&lt;script&gt;&quot;&amp;');
  assert.match(icon('search'), /width="16"/);
  assert.match(icon('search'), /aria-hidden="true"/);
  assert.match(severity(15), /Critical/);
  assert.match(severity(14), /High/);
  assert.match(severity(10), /Medium/);
  assert.match(severity(8), /Medium/);
  assert.match(severity(6), /Low/);
  assert.equal(statusLabel('in_progress'), 'Dalam investigasi');
});
