import {esc, icon} from '../../ui/primitives.js';
import {ERROR_CODE_CATEGORIES, ERROR_CODE_SECTIONS, ERROR_CODES, filterErrorCodeSections} from './model.js';

function sectionBadge(group) {
  const map = {
    '1xx': ['neutral', '1xx Informational'],
    '2xx': ['success', '2xx Success'],
    '3xx': ['neutral', '3xx Redirection'],
    '4xx': ['warning', '4xx Client Error'],
    '5xx': ['critical', '5xx Server Error'],
    vendor: ['neutral', 'Nonstandard / Vendor'],
  };
  const [cls, label] = map[group] || ['neutral', group];
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

export async function mount(ctx) {
  const {root, signal} = ctx;
  let activeCategory = 'all';
  let searchQuery = '';

  function renderSections() {
    const slot = root.querySelector('#ec-results');
    const counter = root.querySelector('#ec-count');
    if (!slot) return;
    const sections = filterErrorCodeSections(ERROR_CODE_SECTIONS, {category: activeCategory, q: searchQuery});
    const matchedCount = sections.reduce((sum, sec) => sum + sec.items.length, 0);
    if (counter) {
      counter.textContent = `${matchedCount} dari ${ERROR_CODES.length} kode (${sections.length} tabel)`;
    }
    if (!sections.length) {
      slot.innerHTML = `<section class="form-section"><p class="meta">Tidak ada kode yang cocok dengan pencarian <strong>${esc(searchQuery)}</strong>.</p></section>`;
      return;
    }
    slot.innerHTML = sections.map(section => `
      <section class="form-section" data-ec-section="${esc(section.id)}" style="width:100%; max-width:none">
        <div class="split" style="align-items:flex-start; gap:var(--space-2); margin-bottom:var(--space-3)">
          <div>
            <h2 class="section-heading">${esc(section.title)}</h2>
            ${section.subtitle ? `<p class="meta" style="max-width:none">${esc(section.subtitle)}</p>` : ''}
          </div>
          ${sectionBadge(section.group)}
        </div>
        <div class="table-region" tabindex="0" aria-label="Tabel ${esc(section.title)}" style="width:100%; max-width:none">
          <table class="data-table" style="width:100%">
            <thead>
              <tr>
                <th style="width:100px">Kode</th>
                <th style="width:300px">Nama Status</th>
                <th>Penjelasan</th>
              </tr>
            </thead>
            <tbody>
              ${section.items.map(item => `
                <tr>
                  <td><strong class="mono" style="font-size:0.95rem">${esc(item.code)}</strong></td>
                  <td><strong>${esc(item.name)}</strong></td>
                  <td style="line-height:1.5">${esc(item.description)}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </section>
    `).join('');
  }

  function render() {
    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading" style="width:100%">
          <h1>Kamus Error Code</h1>
          <p class="page-description" style="max-width:none">Referensi kode status HTTP standar (1xx–5xx) dan kode nonstandar yang dikelompokkan pada tabel terpisah per platform/layanan (IIS, nginx, Cloudflare, AWS ELB, Apache, Laravel, Spring, Twitter, Shopify, ArcGIS, cPanel, SSLLabs, Pantheon, LinkedIn).</p>
        </div>
      </header>

      <div class="stack" style="width:100%; max-width:none">
        <section class="form-section" style="width:100%; max-width:none">
          <div class="toolbar" style="margin-bottom:var(--space-3); flex-wrap:wrap; gap:var(--space-2)">
            <div class="search-field" style="min-width:260px; flex:1; max-width:none">
              <label class="sr-only" for="ec-search">Cari kode atau deskripsi</label>
              ${icon('search')}
              <input
                type="search"
                id="ec-search"
                placeholder="Cari kode (mis. 400, 403, 444, 499, 508, 522) atau layanan (cPanel, nginx, Cloudflare)…"
                value="${esc(searchQuery)}"
                autocomplete="off"
                spellcheck="false"
              >
            </div>
            <span class="meta" id="ec-count"></span>
          </div>

          <div class="tabs" role="tablist" aria-label="Kategori kode" style="flex-wrap:wrap">
            ${ERROR_CODE_CATEGORIES.map(([key, label]) => `
              <button type="button" class="tab" data-ec-cat="${esc(key)}" aria-pressed="${activeCategory === key}">${esc(label)}</button>
            `).join('')}
          </div>
        </section>

        <div id="ec-results" class="stack" style="width:100%; max-width:none"></div>
      </div>
    `;
    renderSections();
  }

  root.addEventListener('input', event => {
    if (event.target.id === 'ec-search') {
      searchQuery = event.target.value;
      renderSections();
    }
  }, {signal});

  root.addEventListener('click', event => {
    const tab = event.target.closest('[data-ec-cat]');
    if (tab) {
      activeCategory = tab.dataset.ecCat;
      for (const btn of root.querySelectorAll('[data-ec-cat]')) {
        btn.setAttribute('aria-pressed', String(btn.dataset.ecCat === activeCategory));
      }
      renderSections();
    }
  }, {signal});

  render();
  return () => {};
}
