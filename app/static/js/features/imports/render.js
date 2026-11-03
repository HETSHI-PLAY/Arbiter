import {esc, icon} from '../../ui/primitives.js';
import {tenantValues} from '../../state/scope.js';

export function importPage() {
  return `<header class="page-header"><div><h1 class="page-heading">Impor alert</h1><p class="page-description">Tambahkan ekspor Wazuh dari file atau teks.</p></div></header>
    <div class="import-layout"><section class="panel stack" aria-labelledby="import-heading">
      <h2 id="import-heading" class="section-heading">Sumber alert</h2>
      <div class="segmented" role="group" aria-label="Sumber impor">
        <button type="button" class="button" data-mode="file" aria-pressed="true">${icon('upload')} Unggah file</button>
        <button type="button" class="button" data-mode="paste" aria-pressed="false">Tempel JSON</button>
      </div>
      <form id="import-form" class="stack" novalidate>
        <div data-panel="file" class="field"><label for="import-file">File alert</label><input id="import-file" class="input" type="file" accept=".json,.jsonl,.txt" aria-describedby="import-format import-file-note"><p id="import-file-note" class="meta">Belum ada file dipilih.</p></div>
        <div data-panel="paste" class="field" hidden><label for="import-content">JSON atau JSONL</label><textarea id="import-content" class="textarea mono" rows="14" spellcheck="false" autocapitalize="off" autocomplete="off" aria-describedby="import-format import-warning" placeholder="Tempel ekspor JSON atau satu objek JSON per baris"></textarea></div>
        <p id="import-format" class="muted">Format .json, .jsonl, atau .txt; encoding UTF-8. Validasi lokal hanya pemeriksaan awal. Server menentukan hasil impor; tidak ada dry-run atau progress persentase.</p>
        <p id="import-warning" class="inline-status" role="status"></p>
        <div id="import-error" class="error-region" role="alert" tabindex="-1" hidden></div>
        <div class="page-actions"><button type="button" class="button" data-action="reset">Kosongkan input</button><button type="submit" class="button primary" id="import-submit">Impor alert</button></div>
        <p id="import-status" class="inline-status" aria-live="polite"></p>
      </form>
    </section><aside class="context-panel stack"><h2 class="section-heading">Tentang impor</h2><p>Tenant dibaca dari data alert, bukan dari tenant yang sedang dibuka.</p><p>Input tidak disimpan di browser. Pertahankan halaman ini selama impor berlangsung. Jika koneksi terputus, periksa Triage sebelum mengirim ulang.</p></aside></div>
    <section id="import-result" class="panel stack" aria-live="polite" tabindex="-1" hidden></section>`;
}

export function importResult(result, scope = 'all') {
  const triageScope = new URLSearchParams();
  for (const tenant of tenantValues(scope)) triageScope.append('tenant', tenant);
  triageScope.set('review_status', 'all');
  return `<h2 class="section-heading">Hasil impor sesi ini</h2><dl class="metric-strip">
    <div><dt>Dibaca</dt><dd>${esc(result.parsed)}</dd></div><div><dt>Ditambahkan</dt><dd>${esc(result.inserted)}</dd></div><div><dt>Digabung sebagai duplikat</dt><dd>${esc(result.deduplicated)}</dd></div>
    </dl>${result.warnings.length ? `<h3 class="section-heading">Peringatan parser</h3><ul>${result.warnings.map(warning => `<li>${esc(warning)}</li>`).join('')}</ul>` : '<p>Tidak ada peringatan dari parser.</p>'}
    <p class="muted">Triage menampilkan semua alert dalam scope tenant yang dipilih, bukan hanya hasil impor ini. Backend tidak menyediakan filter batch impor.</p>
    <div class="page-actions"><a class="button primary" href="#/triage?${esc(triageScope)}">Buka Triage</a><button class="button" type="button" data-action="again">Impor lagi</button></div>`;
}
