export const SIDEBAR_KEY = 'arbiter.sidebar';

export function normalizeSidebarState(value) {
  return value === 'collapsed' ? 'collapsed' : 'expanded';
}

export function readSidebarState(storage) {
  try {
    return normalizeSidebarState(storage?.getItem(SIDEBAR_KEY));
  } catch {
    return 'expanded';
  }
}

export function writeSidebarState(storage, state) {
  try {
    storage?.setItem(SIDEBAR_KEY, normalizeSidebarState(state));
  } catch {}
}

export function toggleSidebarState(state) {
  return normalizeSidebarState(state) === 'collapsed' ? 'expanded' : 'collapsed';
}
