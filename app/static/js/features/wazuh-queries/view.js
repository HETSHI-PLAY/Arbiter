import {json, copyText} from '../../api/client.js';
import {esc, icon, formatTime} from '../../ui/primitives.js';

export async function mount(ctx) {
  const {root, signal, notify, setGuard} = ctx;
  let notepad = '';
  let updatedAt = '';
  let updatedBy = '';
  let savedNotes = [];
  let dirty = false;

  const setDirty = val => {
    dirty = Boolean(val);
    const badge = root.querySelector('#wq-dirty-indicator');
    if (badge) {
      badge.textContent = dirty ? 'Belum disimpan' : (updatedAt ? `Tersimpan · ${formatTime(updatedAt)}${updatedBy ? ` oleh @${updatedBy}` : ''}` : 'Tersimpan');
      badge.className = `badge ${dirty ? 'warning' : 'neutral'}`;
    }
  };

  function renderNotesList() {
    const slot = root.querySelector('#wq-notes-list');
    if (!slot) return;
    if (!savedNotes.length) {
      slot.innerHTML = `<p class="meta">Belum ada catatan rumus terpisah. Gunakan Notepad utama di atas atau simpan potongan rumus baru di bawah.</p>`;
      return;
    }
    slot.innerHTML = savedNotes.map(item => {
      const content = item.content || item.dql || item.lucene || item.dsl || '';
      return `
        <article class="ai-group" data-note-id="${esc(item.id)}">
          <div class="ai-group-head">
            <div>
              <span class="meta">${esc(item.category || 'Catatan')}${item.author ? ` · @${esc(item.author)}` : ''}${item.created_at ? ` · ${esc(formatTime(item.created_at))}` : ''}</span>
              <h3>${esc(item.title)}</h3>
            </div>
            <div class="ai-group-actions">
              <button type="button" class="button primary" data-copy-note="${esc(item.id)}">${icon('copy')} Salin</button>
              <button type="button" class="button" data-append-note="${esc(item.id)}">Masukkan ke Notepad</button>
              <button type="button" class="button" data-delete-note="${esc(item.id)}">${icon('delete')} Hapus</button>
            </div>
          </div>
          <pre class="raw-log mono" style="margin-top:8px; white-space:pre-wrap; word-break:break-word;">${esc(content)}</pre>
        </article>
      `;
    }).join('');
  }

  function render() {
    const statusText = dirty
      ? 'Belum disimpan'
      : (updatedAt ? `Tersimpan · ${formatTime(updatedAt)}${updatedBy ? ` oleh @${updatedBy}` : ''}` : 'Siap');
    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading">
          <h1>Rumus Query Wazuh</h1>
          <p class="page-description">Notepad bersama untuk menulis, menyimpan, dan menyalin rumus query Wazuh (seperti <span class="mono">not ([payload])</span>). Dapat diakses dan digunakan oleh semua pengguna.</p>
        </div>
      </header>

      <div class="stack" style="width:100%; max-width:none">
        <section class="form-section">
          <div class="split" style="align-items:center; gap:var(--space-2); flex-wrap:wrap; margin-bottom:var(--space-2)">
            <div>
              <h2 class="section-heading">Notepad Rumus Query</h2>
              <p class="meta">Tulis bebas seperti Notepad. Tekan <span class="mono">Ctrl+S</span> atau klik <strong>Simpan Notepad</strong> agar tersimpan untuk semua akun.</p>
            </div>
            <div style="display:flex; align-items:center; gap:var(--space-2); flex-wrap:wrap">
              <span class="badge ${dirty ? 'warning' : 'neutral'}" id="wq-dirty-indicator">${esc(statusText)}</span>
              <button type="button" class="button" data-action="insert-not">Sisipkan <span class="mono" style="margin-left:4px">not (...)</span></button>
              <button type="button" class="button" data-action="copy-notepad">${icon('copy')} Salin Notepad</button>
              <button type="button" class="button primary" id="wq-save-notepad-btn" data-action="save-notepad">${icon('check')} Simpan Notepad</button>
            </div>
          </div>

          <textarea
            id="wq-notepad"
            class="input mono"
            rows="16"
            spellcheck="false"
            placeholder="Contoh:&#10;not (&quot;payload_1&quot; or &quot;payload_2&quot;)&#10;&#10;atau catatan filter query Wazuh sehari-hari…"
            style="width:100%; min-height:340px; font-family:var(--font-mono); font-size:0.9rem; line-height:1.55; resize:vertical; padding:var(--space-3);"
          >${esc(notepad)}</textarea>
        </section>

        <section class="form-section">
          <div class="split" style="align-items:center; justify-content:space-between; flex-wrap:wrap; gap:var(--space-2)">
            <div>
              <h2 class="section-heading">Daftar Catatan / Snippet Rumus</h2>
              <p class="meta">Simpan potongan rumus yang sering dipakai agar mudah disalin kapan saja tanpa tertimpa.</p>
            </div>
          </div>

          <form id="wq-note-form" class="stack" style="margin-top:var(--space-3); padding-bottom:var(--space-3); border-bottom:1px solid var(--border-subtle)" novalidate>
            <div class="form-grid">
              <div class="field">
                <label for="wq-note-title">Judul catatan</label>
                <input class="input" id="wq-note-title" name="title" type="text" placeholder="Contoh: Filter Noise Web Tenant A" required>
              </div>
              <div class="field">
                <label for="wq-note-category">Label / Kategori (opsional)</label>
                <input class="input" id="wq-note-category" name="category" type="text" placeholder="Contoh: Exclude / Payload / Tenant">
              </div>
            </div>
            <div class="field">
              <div class="split" style="align-items:center; margin-bottom:4px">
                <label for="wq-note-content">Isi rumus query</label>
                <button type="button" class="text-button meta" data-action="fill-from-notepad">Ambil dari teks Notepad di atas</button>
              </div>
              <textarea
                id="wq-note-content"
                name="content"
                class="input mono"
                rows="4"
                spellcheck="false"
                placeholder="not ([payload])"
                style="width:100%; font-family:var(--font-mono); resize:vertical;"
                required
              ></textarea>
            </div>
            <div class="settings-actions">
              <button type="submit" class="button">${icon('plus')} Tambah ke Daftar Catatan</button>
            </div>
          </form>

          <div id="wq-notes-list" class="ai-groups" style="margin-top:var(--space-3)"></div>
        </section>
      </div>
    `;
    renderNotesList();
  }

  async function saveNotepad() {
    const textarea = root.querySelector('#wq-notepad');
    const btn = root.querySelector('#wq-save-notepad-btn');
    if (!textarea) return;
    notepad = textarea.value;
    if (btn) btn.disabled = true;
    try {
      const res = await json('/api/wazuh-queries', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({notepad}),
        signal,
      });
      notepad = String(res.notepad ?? notepad);
      updatedAt = String(res.updated_at || '');
      updatedBy = String(res.updated_by || '');
      setDirty(false);
      notify('Notepad rumus query berhasil disimpan.', 'success');
    } catch (err) {
      if (err.name !== 'AbortError') notify(err.message || 'Gagal menyimpan notepad.', 'error');
    } finally {
      if (btn?.isConnected) btn.disabled = false;
    }
  }

  root.addEventListener('input', event => {
    if (event.target.id === 'wq-notepad') {
      notepad = event.target.value;
      setDirty(true);
    }
  }, {signal});

  root.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') {
      if (root.querySelector('#wq-notepad')) {
        event.preventDefault();
        saveNotepad();
      }
    }
  }, {signal});

  root.addEventListener('click', async event => {
    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'save-notepad') {
      await saveNotepad();
      return;
    }
    if (action === 'copy-notepad') {
      const val = root.querySelector('#wq-notepad')?.value || '';
      await copyText(val);
      notify('Isi Notepad disalin ke clipboard.', 'success');
      return;
    }
    if (action === 'insert-not') {
      const ta = root.querySelector('#wq-notepad');
      if (!ta) return;
      const start = ta.selectionStart ?? ta.value.length;
      const end = ta.selectionEnd ?? ta.value.length;
      const selected = ta.value.slice(start, end);
      const snippet = selected ? `not (${selected})` : 'not ("")';
      ta.setRangeText(snippet, start, end, 'end');
      ta.focus();
      notepad = ta.value;
      setDirty(true);
      return;
    }
    if (action === 'fill-from-notepad') {
      const ta = root.querySelector('#wq-notepad');
      const noteTa = root.querySelector('#wq-note-content');
      if (ta && noteTa) {
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        const selected = start !== end ? ta.value.slice(start, end).trim() : '';
        noteTa.value = selected || ta.value.trim();
        noteTa.focus();
      }
      return;
    }

    const copyBtn = event.target.closest('[data-copy-note]');
    if (copyBtn) {
      const note = savedNotes.find(n => String(n.id) === copyBtn.dataset.copyNote);
      const text = note?.content || note?.dql || note?.lucene || note?.dsl || '';
      await copyText(text);
      notify(`Rumus "${note?.title || ''}" disalin ke clipboard.`, 'success');
      return;
    }

    const appendBtn = event.target.closest('[data-append-note]');
    if (appendBtn) {
      const note = savedNotes.find(n => String(n.id) === appendBtn.dataset.appendNote);
      const text = note?.content || note?.dql || note?.lucene || note?.dsl || '';
      const ta = root.querySelector('#wq-notepad');
      if (ta && text) {
        ta.value = ta.value.trim() ? `${ta.value.trimEnd()}\n\n${text}` : text;
        notepad = ta.value;
        setDirty(true);
        ta.focus();
        notify(`Rumus "${note?.title || ''}" dimasukkan ke Notepad.`, 'info');
      }
      return;
    }

    const deleteBtn = event.target.closest('[data-delete-note]');
    if (deleteBtn) {
      const id = deleteBtn.dataset.deleteNote;
      deleteBtn.disabled = true;
      try {
        const res = await json(`/api/wazuh-queries/${encodeURIComponent(id)}`, {method: 'DELETE', signal});
        savedNotes = Array.isArray(res?.items) ? res.items : [];
        renderNotesList();
        notify('Catatan rumus dihapus.', 'info');
      } catch (err) {
        if (err.name !== 'AbortError') notify(err.message || 'Gagal menghapus catatan.', 'error');
      } finally {
        if (deleteBtn.isConnected) deleteBtn.disabled = false;
      }
    }
  }, {signal});

  root.addEventListener('submit', async event => {
    const form = event.target.closest('#wq-note-form');
    if (!form) return;
    event.preventDefault();
    const title = form.elements.title.value.trim();
    const category = form.elements.category.value.trim() || 'Catatan';
    const content = form.elements.content.value.trim();
    if (!title || !content) {
      notify('Isi judul dan rumus query terlebih dahulu.', 'error');
      return;
    }
    const submitBtn = form.querySelector('button[type=submit]');
    if (submitBtn) submitBtn.disabled = true;
    try {
      const res = await json('/api/wazuh-queries', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({title, category, content}),
        signal,
      });
      savedNotes = Array.isArray(res?.items) ? res.items : [];
      form.reset();
      renderNotesList();
      notify('Catatan rumus berhasil ditambahkan.', 'success');
    } catch (err) {
      if (err.name !== 'AbortError') notify(err.message || 'Gagal menyimpan catatan.', 'error');
    } finally {
      if (submitBtn?.isConnected) submitBtn.disabled = false;
    }
  }, {signal});

  setGuard?.(() => !dirty);
  render();

  try {
    const res = await json('/api/wazuh-queries', {signal});
    if (signal.aborted) return () => {};
    notepad = String(res?.notepad || '');
    updatedAt = String(res?.updated_at || '');
    updatedBy = String(res?.updated_by || '');
    savedNotes = Array.isArray(res?.items) ? res.items : [];
    setDirty(false);
    render();
  } catch {
    // Non-fatal
  }

  return () => {};
}
