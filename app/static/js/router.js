export function parseRoute(hash = '') {
  const raw = hash.replace(/^#/, '') || '/triage';
  const [pathPart, search = ''] = raw.split('?');
  const path = pathPart.startsWith('/') ? pathPart : '/triage';
  const first = path.split('/')[1];
  return {path, params: new URLSearchParams(search), page: ['triage', 'stats', 'incidents', 'imports', 'reports', 'realtime', 'ai-triage', 'wazuh-queries', 'error-codes', 'database', 'settings'].includes(first) ? first : 'not-found'};
}
export const withParams = (path, params) => `#${path}${params?.size ? `?${params}` : ''}`;
export function createRouter(onChange, canLeave = () => true) {
  let current = location.hash || '#/triage';
  let skip = false;
  function change() {
    if (skip) { skip = false; return; }
    const next = location.hash || '#/triage';
    if (!canLeave(parseRoute(next))) {
      skip = true; location.hash = current; return;
    }
    const old = current; current = next; onChange(parseRoute(next), {previous: old});
  }
  const sync = () => { current = location.hash || '#/triage'; };
  window.addEventListener('hashchange', change);
  window.addEventListener('arbiter:route-replaced', sync);
  if (!location.hash) history.replaceState(null, '', current);
  return {
    start() { onChange(parseRoute(current), {initial: true}); },
    navigate(target, {replace = false} = {}) {
      const hash = target.startsWith('#') ? target : `#${target}`;
      if (hash === current) return;
      if (replace) {
        if (!canLeave(parseRoute(hash))) return;
        const old = current; current = hash; history.replaceState(null, '', hash); onChange(parseRoute(hash), {previous: old});
      } else location.hash = hash;
    },
    dispose() { window.removeEventListener('hashchange', change); window.removeEventListener('arbiter:route-replaced', sync); },
  };
}
