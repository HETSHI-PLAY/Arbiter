export async function importFeature(page, {load = specifier => import(specifier), now = () => Date.now()} = {}) {
  const specifier = `./features/${page}/view.js`;
  try {
    return await load(specifier);
  } catch (error) {
    if (error?.name === 'AbortError') throw error;
    // Browsers cache a failed dynamic import against its URL, so "Coba lagi" would
    // replay the same failure until a full page reload. Retry once with a fresh
    // URL so the module is fetched from the server again and can recover itself.
    return load(`${specifier}?retry=${now()}`);
  }
}
