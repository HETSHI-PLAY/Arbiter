import {json, copyText} from '../../api/client.js';
import {esc, icon} from '../../ui/primitives.js';
import {
  PRESET_CATEGORIES,
  PRESET_WAZUH_QUERIES,
  QUERY_SEVERITY_OPTIONS,
  QUERY_TIME_OPTIONS,
  buildWazuhQueries,
} from './model.js';

export async function mount(ctx) {
  const {root, signal, notify} = ctx;
  let savedQueries = [];
  let tenantList = [];
  let activeCategory = 'Semua';
  let searchFilter = '';
  let activeFormatTab = 'dql';

  const builder = {
    tenant: '',
    severity: '7-11',
    agentName: '',
    sourceIp: '',
    ruleIds: '',
    searchKeyword: '',
    excludeNoise: true,
    timeRange: 'now-24h',
    size: 500,
  };

  function currentBuilt() {
    return buildWazuhQueries(builder);
  }

  function renderBuilderOutput() {
    const slot = root.querySelector('#wq-builder-output');
    if (!slot) return;
    const built = currentBuilt();
    const textMap = {
      dql: built.dql,
      dsl: built.dsl,
      lucene: built.lucene,
      curl: built.curl,
    };
    const labelMap = {
      dql: 'Wazuh Dashboard (DQL / KQL)',
      dsl: 'OpenSearch / Elasticsearch Query DSL (JSON)',
      lucene: 'Lucene Query Syntax',
      curl: 'Perintah cURL Wazuh Indexer API',
    };
    const activeText = textMap[activeFormatTab] || built.dql;
    slot.innerHTML = `
      <div class="split" style="margin-bottom:8px;">
        <div class="tabs" role="tablist" aria-label="Format rumus query">
          ${[
            ['dql', 'DQL / KQL (Dashboard)'],
            ['dsl', 'OpenSearch DSL (JSON)'],
            ['lucene', 'Lucene'],
            ['curl', 'cURL API'],
          ].map(([key, label]) => `<button type="button" class="tab" data-format-tab="${key}" aria-pressed="${activeFormatTab === key}">${esc(label)}</button>`).join('')}
        </div>
        <div class="page-actions">
          <button type="button" class="button primary" data-action="copy-builder-output">${icon('copy')} Salin ${esc(labelMap[activeFormatTab])}</button>
        </div>
      </div>
      <pre class="raw-log mono" id="wq-generated-code" style="max-height:280px; overflow:auto;">${esc(activeText)}</pre>
    `;
  }

  function renderCatalog() {
    const slot = root.querySelector('#wq-catalog-list');
    if (!slot) return;
    const allItems = [
      ...savedQueries.map(item => ({...item, isCustom: true, category: item.category || 'Kustom'})),
      ...PRESET_WAZUH_QUERIES.map(item => ({...item, isCustom: false})),
    ];
    const q = searchFilter.trim().toLowerCase();
    const filtered = allItems.filter(item => {
      if (activeCategory !== 'Semua' && item.category !== activeCategory) return false;
      if (!q) return true;
      const hay = `${item.title} ${item.category} ${item.description} ${item.dql} ${item.lucene}`.toLowerCase();
      return hay.includes(q);
    });

    if (!filtered.length) {
      slot.innerHTML = `<p class="meta">Tidak ada rumus query yang cocok dengan filter saat ini.</p>`;
      return;
    }

    slot.innerHTML = filtered.map((item, idx) => `
      <article class="ai-group" data-query-card="${idx}">
        <div class="ai-group-head">
          <div>
            <span class="meta">${esc(item.category)}${item.isCustom ? ` · Disimpan oleh ${esc(item.author || 'tim')}` : ' · Standar SOC'}</span>
            <h3>${esc(item.title)}</h3>
          </div>
          <div>
            <span class="badge ${item.isCustom ? 'success' : 'neutral'}">${item.isCustom ? 'Rumus Tim' : 'Preset'}</span>
          </div>
        </div>
        <p class="ai-group-reason">${esc(item.description || '')}</p>
        <div class="stack" style="gap:8px; margin-top:8px;">
          ${item.dql ? `<div><span class="meta"><strong>DQL / KQL (Wazuh Dashboard):</strong></span><pre class="raw-log mono" style="margin-top:4px; padding:8px;">${esc(item.dql)}</pre></div>` : ''}
          ${item.lucene ? `<div><span class="meta"><strong>Lucene:</strong></span><pre class="raw-log mono" style="margin-top:4px; padding:8px;">${esc(item.lucene)}</pre></div>` : ''}
          ${item.dsl ? `<details><summary class="text-button meta">Lihat OpenSearch Query DSL (JSON)</summary><pre class="raw-log mono" style="margin-top:6px; max-height:220px; overflow:auto;">${esc(item.dsl)}</pre></details>` : ''}
        </div>
        <div class="ai-group-actions" style="margin-top:10px;">
          ${item.dql ? `<button type="button" class="button primary" data-copy-text="${esc(item.dql)}" data-copy-label="DQL/KQL">${icon('copy')} Salin DQL/KQL</button>` : ''}
          ${item.dsl ? `<button type="button" class="button" data-copy-text="${esc(item.dsl)}" data-copy-label="OpenSearch JSON">${icon('copy')} Salin JSON DSL</button>` : ''}
          ${item.lucene ? `<button type="button" class="button" data-copy-text="${esc(item.lucene)}" data-copy-label="Lucene">${icon('copy')} Salin Lucene</button>` : ''}
          ${item.builderDefaults ? `<button type="button" class="button" data-load-preset="${esc(item.id)}">${icon('spark')} Gunakan di Generator</button>` : ''}
          ${item.isCustom ? `<button type="button" class="button" data-delete-query="${esc(item.id)}">${icon('delete')} Hapus</button>` : ''}
        </div>
      </article>
    `).join('');
  }

  function render() {
    const categories = [...PRESET_CATEGORIES, 'Kustom'];
    const tenantDatalist = tenantList.map(t => `<option value="${esc(t)}"></option>`).join('');
    root.innerHTML = `
      <header class="page-header">
        <div class="page-heading">
          <h1>Rumus Query Wazuh</h1>
          <p class="page-description">Generator interaktif dan katalog rumus query Wazuh (DQL/KQL Dashboard, OpenSearch JSON DSL, Lucene, dan cURL API). Halaman ini dapat diakses oleh seluruh analis dan pengguna.</p>
        </div>
      </header>

      <div class="settings-layout">
        <section class="form-section">
          <div class="split">
            <div>
              <h2 class="section-heading">Generator Rumus Query Interaktif</h2>
              <p class="meta">Susun parameter filter di bawah ini untuk menghasilkan rumus query Wazuh siap salin secara otomatis.</p>
            </div>
            <button type="button" class="button" data-action="reset-builder">${icon('refresh')} Reset generator</button>
          </div>

          <form id="wq-builder-form" class="form-grid" novalidate>
            <div class="field">
              <label for="wq-severity">Ambang severity</label>
              <select class="select" id="wq-severity" name="severity">
                ${QUERY_SEVERITY_OPTIONS.map(([val, label]) => `<option value="${esc(val)}" ${builder.severity === val ? 'selected' : ''}>${esc(label)}</option>`).join('')}
              </select>
            </div>
            <div class="field">
              <label for="wq-tenant">Tenant (<span class="mono">agent.labels.tenant</span>)</label>
              <input class="input" id="wq-tenant" name="tenant" type="text" list="wq-tenant-list" placeholder="Kosongkan untuk semua tenant" value="${esc(builder.tenant)}">
              <datalist id="wq-tenant-list">${tenantDatalist}</datalist>
            </div>
            <div class="field">
              <label for="wq-agent">Nama Agent / Host (<span class="mono">agent.name</span>)</label>
              <input class="input mono" id="wq-agent" name="agentName" type="text" placeholder="Contoh: web-prod-01" value="${esc(builder.agentName)}">
            </div>
            <div class="field">
              <label for="wq-srcip">Source IP (<span class="mono">data.srcip</span>)</label>
              <input class="input mono" id="wq-srcip" name="sourceIp" type="text" placeholder="Contoh: 198.51.100.77" value="${esc(builder.sourceIp)}">
            </div>
            <div class="field">
              <label for="wq-rule-ids">Rule ID (<span class="mono">rule.id</span>, pisahkan koma)</label>
              <input class="input mono" id="wq-rule-ids" name="ruleIds" type="text" placeholder="Contoh: 31101, 5710, 5712" value="${esc(builder.ruleIds)}">
            </div>
            <div class="field">
              <label for="wq-keyword">Kata Kunci Payload / URI / Log</label>
              <input class="input mono" id="wq-keyword" name="searchKeyword" type="text" placeholder="Contoh: /cgi-bin/ atau LeakIX" value="${esc(builder.searchKeyword)}">
            </div>
            <div class="field">
              <label for="wq-time">Rentang waktu (OpenSearch DSL)</label>
              <select class="select" id="wq-time" name="timeRange">
                ${QUERY_TIME_OPTIONS.map(([val, label]) => `<option value="${esc(val)}" ${builder.timeRange === val ? 'selected' : ''}>${esc(label)}</option>`).join('')}
              </select>
            </div>
            <div class="field">
              <label for="wq-size">Maksimum dokumen (<span class="mono">size</span>)</label>
              <input class="input mono" id="wq-size" name="size" type="number" min="1" max="5000" step="1" value="${esc(builder.size)}">
            </div>
          </form>

          <label class="checkbox-label" style="margin-top:8px;">
            <input type="checkbox" id="wq-exclude-noise" ${builder.excludeNoise ? 'checked' : ''}>
            Kecualikan noise Active Response (<span class="mono">NOT rule.id: 651, 652</span>)
          </label>

          <div id="wq-builder-output" style="margin-top:14px;"></div>

          <details style="margin-top:12px;">
            <summary class="button">${icon('plus')} Simpan rumus ini ke Katalog Tim</summary>
            <form id="wq-save-custom-form" class="form-grid" style="margin-top:12px;">
              <div class="field">
                <label for="wq-custom-title">Judul rumus</label>
                <input class="input" id="wq-custom-title" name="title" type="text" required placeholder="Contoh: Deteksi Brute Force Tenant Alpha">
              </div>
              <div class="field">
                <label for="wq-custom-category">Kategori</label>
                <input class="input" id="wq-custom-category" name="category" type="text" value="Kustom" placeholder="Kustom / Web Exploit / Severity">
              </div>
              <div class="field" style="grid-column: 1 / -1;">
                <label for="wq-custom-desc">Catatan / penjelasan singkat</label>
                <input class="input" id="wq-custom-desc" name="description" type="text" placeholder="Kapan rumus ini dipakai oleh analis SOC…">
              </div>
              <div class="settings-actions" style="grid-column: 1 / -1;">
                <button type="submit" class="button primary">${icon('check')} Simpan Rumus ke Katalog</button>
              </div>
            </form>
          </details>
        </section>

        <section class="form-section">
          <div class="split">
            <div>
              <h2 class="section-heading">Katalog Rumus Query Wazuh</h2>
              <p class="meta">Kumpulan rumus standar SOC dan rumus kustom tim yang siap disalin ke Wazuh Dashboard maupun API Indexer.</p>
            </div>
          </div>

          <div class="toolbar" style="margin:12px 0;">
            <div class="search-field">
              <label class="sr-only" for="wq-catalog-search">Cari rumus query</label>
              ${icon('search')}
              <input type="search" id="wq-catalog-search" placeholder="Cari rumus, rule ID, traversal, brute force…" value="${esc(searchFilter)}">
            </div>
            <div class="tabs" role="tablist" aria-label="Kategori rumus">
              ${categories.map(cat => `<button type="button" class="tab" data-cat-tab="${esc(cat)}" aria-pressed="${activeCategory === cat}">${esc(cat)}</button>`).join('')}
            </div>
          </div>

          <div id="wq-catalog-list" class="ai-groups"></div>
        </section>
      </div>
    `;
    renderBuilderOutput();
    renderCatalog();
  }

  function syncBuilderFromDOM() {
    const form = root.querySelector('#wq-builder-form');
    if (!form) return;
    builder.severity = form.elements.severity.value;
    builder.tenant = form.elements.tenant.value;
    builder.agentName = form.elements.agentName.value;
    builder.sourceIp = form.elements.sourceIp.value;
    builder.ruleIds = form.elements.ruleIds.value;
    builder.searchKeyword = form.elements.searchKeyword.value;
    builder.timeRange = form.elements.timeRange.value;
    builder.size = Number(form.elements.size.value) || 500;
    builder.excludeNoise = Boolean(root.querySelector('#wq-exclude-noise')?.checked);
    renderBuilderOutput();
  }

  root.addEventListener('input', event => {
    if (event.target.closest('#wq-builder-form') || event.target.id === 'wq-exclude-noise') {
      syncBuilderFromDOM();
    } else if (event.target.id === 'wq-catalog-search') {
      searchFilter = event.target.value;
      renderCatalog();
    }
  }, {signal});

  root.addEventListener('change', event => {
    if (event.target.closest('#wq-builder-form') || event.target.id === 'wq-exclude-noise') {
      syncBuilderFromDOM();
    }
  }, {signal});

  root.addEventListener('click', async event => {
    const formatBtn = event.target.closest('[data-format-tab]');
    if (formatBtn) {
      activeFormatTab = formatBtn.dataset.formatTab;
      renderBuilderOutput();
      return;
    }

    const catBtn = event.target.closest('[data-cat-tab]');
    if (catBtn) {
      activeCategory = catBtn.dataset.catTab;
      render();
      return;
    }

    const copyBtn = event.target.closest('[data-copy-text]');
    if (copyBtn) {
      await copyText(copyBtn.dataset.copyText);
      notify(`Rumus ${copyBtn.dataset.copyLabel || 'query'} disalin ke clipboard.`, 'success');
      return;
    }

    const presetBtn = event.target.closest('[data-load-preset]');
    if (presetBtn) {
      const preset = PRESET_WAZUH_QUERIES.find(p => p.id === presetBtn.dataset.loadPreset);
      if (preset?.builderDefaults) {
        Object.assign(builder, {
          tenant: '',
          severity: '7-11',
          agentName: '',
          sourceIp: '',
          ruleIds: '',
          searchKeyword: '',
          excludeNoise: true,
          timeRange: 'now-24h',
          size: 500,
          ...preset.builderDefaults,
        });
        render();
        notify(`Preset "${preset.title}" dimuat ke Generator.`, 'info');
      }
      return;
    }

    const deleteBtn = event.target.closest('[data-delete-query]');
    if (deleteBtn) {
      const qid = deleteBtn.dataset.deleteQuery;
      deleteBtn.disabled = true;
      try {
        const res = await json(`/api/wazuh-queries/${encodeURIComponent(qid)}`, {method: 'DELETE', signal});
        savedQueries = res.items || [];
        renderCatalog();
        notify('Rumus kustom dihapus.', 'info');
      } catch (err) {
        if (err.name !== 'AbortError') notify(err.message, 'error');
      } finally {
        if (deleteBtn.isConnected) deleteBtn.disabled = false;
      }
      return;
    }

    const action = event.target.closest('[data-action]')?.dataset.action;
    if (action === 'copy-builder-output') {
      const built = currentBuilt();
      const text = built[activeFormatTab] || built.dql;
      await copyText(text);
      notify('Rumus query dari generator berhasil disalin.', 'success');
    } else if (action === 'reset-builder') {
      Object.assign(builder, {
        tenant: '',
        severity: '7-11',
        agentName: '',
        sourceIp: '',
        ruleIds: '',
        searchKeyword: '',
        excludeNoise: true,
        timeRange: 'now-24h',
        size: 500,
      });
      render();
    }
  }, {signal});

  root.addEventListener('submit', async event => {
    const saveForm = event.target.closest('#wq-save-custom-form');
    if (!saveForm) return;
    event.preventDefault();
    const built = currentBuilt();
    const title = saveForm.elements.title.value.trim();
    const category = saveForm.elements.category.value.trim() || 'Kustom';
    const description = saveForm.elements.description.value.trim();
    if (!title) {
      notify('Isi judul rumus terlebih dahulu.', 'error');
      return;
    }
    const submitBtn = saveForm.querySelector('button[type=submit]');
    if (submitBtn) submitBtn.disabled = true;
    try {
      const res = await json('/api/wazuh-queries', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          title,
          category,
          description,
          dql: built.dql,
          dsl: built.dsl,
          lucene: built.lucene,
        }),
        signal,
      });
      savedQueries = res.items || [];
      saveForm.reset();
      renderCatalog();
      notify('Rumus query disimpan ke katalog tim.', 'success');
    } catch (err) {
      if (err.name !== 'AbortError') notify(err.message, 'error');
    } finally {
      if (submitBtn?.isConnected) submitBtn.disabled = false;
    }
  }, {signal});

  render();

  try {
    const [qRes, tRes] = await Promise.all([
      json('/api/wazuh-queries', {signal}).catch(() => ({items: []})),
      json('/api/tenants', {signal}).catch(() => ({tenants: []})),
    ]);
    if (signal.aborted) return () => {};
    savedQueries = Array.isArray(qRes?.items) ? qRes.items : [];
    tenantList = Array.isArray(tRes?.tenants) ? tRes.tenants.map(r => String(r.tenant)).filter(Boolean) : [];
    render();
  } catch {
    // Non-fatal
  }

  return () => {};
}

