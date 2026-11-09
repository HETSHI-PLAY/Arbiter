import test from 'node:test';
import assert from 'node:assert/strict';
import {importFeature} from '../../app/static/js/feature-loader.js';

test('a failed feature import is retried once with a cache-busting URL', async () => {
  const attempts = [];
  const module = {mount() {}};
  const result = await importFeature('triage', {
    now: () => 1234,
    load: async specifier => {
      attempts.push(specifier);
      if (attempts.length === 1) throw new TypeError('Failed to fetch dynamically imported module');
      return module;
    },
  });
  assert.equal(result, module);
  assert.deepEqual(attempts, ['./features/triage/view.js', './features/triage/view.js?retry=1234']);
});

test('a successful feature import is not retried', async () => {
  const attempts = [];
  await importFeature('stats', {load: async specifier => { attempts.push(specifier); return {}; }});
  assert.deepEqual(attempts, ['./features/stats/view.js']);
});

test('abort errors are never retried', async () => {
  const attempts = [];
  const abort = Object.assign(new Error('aborted'), {name: 'AbortError'});
  await assert.rejects(
    importFeature('triage', {load: async specifier => { attempts.push(specifier); throw abort; }}),
    /aborted/,
  );
  assert.deepEqual(attempts, ['./features/triage/view.js']);
});

test('a persistent failure rejects with the retry error after one fresh attempt', async () => {
  const attempts = [];
  await assert.rejects(
    importFeature('incidents', {
      load: async specifier => { attempts.push(specifier); throw new SyntaxError(`broken ${specifier}`); },
      now: () => 99,
    }),
    /broken .*retry=99/,
  );
  assert.equal(attempts.length, 2);
});
