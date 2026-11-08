import {json, apiURL, copyText} from '../../api/client.js';
import {esc, icon, severity, formatTime, emptyState, errorState, loadingRows, defangText} from '../../ui/primitives.js';
import {queryFrom, scopeParams} from '../../state/scope.js';
import {withParams} from '../../router.js';
import {createTriageSession} from '../../state/triage.js';
import {intelSummary, intelBadge, renderQueue, renderTriageSummary, summaryRequestParams} from './model.js';

const presets = [['','Semua jenis'],['403','403 Forbidden'],['404','404 Probes'],['repeating','Berulang'],['non_http','Non-HTTP'],['bot','Bot traffic'],['curl','Curl requests']];
const verdictLabels = {tp:'True Positive',fp:'False Positive',needs_review:'Perlu ditinjau'};
const roleLabels = {indicator:'Indikator',response:'Respons',context:'Konteks',unknown:'Belum diketahui'};
const priorityLabels = {low:'Rendah',medium:'Sedang',high:'Tinggi',critical:'Kritis'};
const verdictClass = verdict => verdict==='tp'?'critical':verdict==='fp'?'info':'warning';

function classificationBlock(alert) {
  const intel = alert?.parsed_details?.wazuh_intel;
  if (!intel || !intel.verdict) return '';
  const verdict = verdictLabels[intel.verdict] || intel.verdict;
  const role = roleLabels[intel.role] || intel.role || '—';
  const priority = priorityLabels[intel.priority] || intel.priority || '—';
  const confidence = Number(intel.confidence);
  const signals = Array.isArray(intel.signals) ? intel.signals.slice(0, 8) : [];
  const origin = intel.origin && typeof intel.origin === 'object' ? intel.origin : null;
  return `<section class="stack" aria-label="Klasifikasi alert">
    <div class="split"><h3>Klasifikasi</h3><span class="badge ${verdictClass(intel.verdict)}">${esc(verdict)}</span></div>
    <p class="meta">${esc(role)} · keyakinan ${Number.isFinite(confidence) ? Math.round(confidence * 100) + '%' : '—'} · prioritas ${esc(priority)}</p>
    <p>${esc(intel.reason || 'Belum ada alasan klasifikasi.')}</p>
    ${signals.length ? `<ul class="stack meta" aria-label="Sinyal klasifikasi">${signals.map(signal => `<li><strong>${esc(signal.label || signal.code || 'Sinyal')}</strong>: ${esc(signal.value || '—')}</li>`).join('')}</ul>` : ''}
    ${origin ? `<div class="notice" data-kind="info"><p><strong>Alert asal:</strong> Rule ${esc(origin.rule_id || '—')} · ${esc(origin.description || 'tanpa deskripsi')}${origin.source_ip ? ` · <span class="mono">${esc(origin.source_ip)}</span>` : ''}${intel.origin_verdict ? ` · verdict asal: ${esc(verdictLabels[intel.origin_verdict] || intel.origin_verdict)}` : ''}</p></div>` : ''}
  </section>`;
}

function chainLine(group) {
  const steps = Array.isArray(group?.chain)
    ? group.chain.filter(step => step.stage !== 'active_response').map(step => step.label).filter(Boolean)
    : [];
  return steps.length ? `<p class="meta">Tahapan: ${esc(steps.join(' → '))}</p>` : '';
}
export function mount(ctx) {
  const {root, route, signal, selection, navigate, notify} = ctx;
  const query = queryFrom(route.params);
  const tenant = query.tenantScope.all ? 'all' : query.tenants;
  const tenantParams = () => {const params=new URLSearchParams();for(const value of query.tenantScope.all?['all']:query.tenants)params.append('tenant',value);return params;};
  const scopedRoute = (path, extra = {}) => {const params=tenantParams();for(const [key,value] of Object.entries(extra))value===undefined||value===null||value===''?params.delete(key):params.set(key,String(value));return withParams(path,params);};
  root.classList.add('triage-page');
  const session = createTriageSession();
  let items = [], total = 0, pageRequest, detailRequest, summaryRequest = null, summaryData = null, isSummaryCollapsed = route.params.get('summary') === 'collapsed', generation = 0, currentAlert = null, lastSelected = null, searchTimer;
  let activeTab = 'detail', activeId = route.params.get('alert'), showIntel = true, wrapLog = true, showAllLogs = false, expandedLogIds = new Set();
  root.innerHTML = `<div class="page-header"><div class="page-heading"><h1>Triage</h1><p class="page-description">Periksa bukti. Tentukan langkah berikutnya.</p></div><div class="page-actions"><a class="button primary" href="${scopedRoute('/imports')}">${icon('upload')}Impor</a></div></div>
    <div class="tabs" aria-label="Antrean review">${[['unreviewed','Belum direview'],['all','Semua'],['reviewed','Direview']].map(([key,label])=>`<button class="tab" data-review="${key}" aria-pressed="${query.review_status===key}">${label}</button>`).join('')}</div>
    <div class="toolbar"><div class="search-field"><label class="sr-only" for="triage-search">Cari alert</label>${icon('search')}<input type="search" id="triage-search" name="q" value="${esc(query.q)}" placeholder="Cari IP, asset, rule…" autocomplete="off" spellcheck="false"></div><button class="button" data-action="filters">${icon('filter')}Filter${query.filter_preset||query.status!=='all'||query.group_id||query.alert_ids||query.time_preset||query.time_from?' aktif':''}</button><button class="button" data-action="toggle-all-queue-logs" id="btn-toggle-queue-logs" aria-pressed="false" title="Tampilkan atau sembunyikan full log semua alert">${icon('cases')}Semua log</button><label class="sr-only" for="triage-sort">Urutan alert</label><select class="sort-control" id="triage-sort" name="sort"><option value="timestamp:desc">Terbaru</option><option value="timestamp:asc">Kronologis</option><option value="severity:desc">Severity tertinggi</option><option value="hits:desc">Hits terbanyak</option></select><button class="button icon-button" data-action="more" aria-label="Opsi antrean" aria-controls="queue-options" aria-expanded="false">${icon('more')}</button></div>
    <div id="queue-options" class="toolbar" hidden><label class="checkbox-label"><input type="checkbox" id="show-intel" checked>Kolom source / intel</label><button class="button" data-action="correlation">Korelasi</button><button class="button" data-action="report-query">Laporan hasil filter</button></div>
    <div id="applied-filters" class="applied-filters"></div><div id="triage-summary-slot"></div><div id="correlation-slot"></div>
    <div class="triage-workspace" id="triage-workspace"><section class="queue-region" aria-label="Antrean kerja"><div id="selection-actions"></div><div id="queue-results">${loadingRows()}</div><div class="pagination" id="queue-pagination"></div></section><aside id="alert-inspector" class="inspector" aria-label="Detail alert" hidden></aside></div>
    <dialog class="filter-dialog" id="triage-filter-dialog" aria-labelledby="filter-title"><div class="dialog-header"><h2 id="filter-title">Filter &amp; urutan</h2><button class="button icon-button" data-close-filter aria-label="Tutup filter">${icon('close')}</button></div><form id="triage-filter-form" class="filter-form"><div class="field"><label for="filter-preset">Jenis event</label><select id="filter-preset" name="filter_preset">${presets.map(([v,l])=>`<option value="${v}" ${v===query.filter_preset?'selected':''}>${l}</option>`).join('')}</select></div><div class="field"><label for="filter-membership">Keanggotaan insiden</label><select id="filter-membership" name="status"><option value="all">Semua</option><option value="ungrouped">Belum masuk insiden</option><option value="grouped">Sudah masuk insiden</option></select></div><div class="field"><label for="filter-time-preset">Rentang waktu telemetri</label><select id="filter-time-preset" name="time_preset"><option value="" ${!query.time_preset?'selected':''}>Semua waktu</option><option value="1h" ${query.time_preset==='1h'?'selected':''}>1 jam terakhir</option><option value="24h" ${query.time_preset==='24h'?'selected':''}>24 jam terakhir</option><option value="7d" ${query.time_preset==='7d'?'selected':''}>7 hari terakhir</option><option value="30d" ${query.time_preset==='30d'?'selected':''}>30 hari terakhir</option><option value="custom" ${query.time_preset==='custom'||(query.time_from&&!query.time_preset)?'selected':''}>Rentang kustom…</option></select></div><div id="filter-custom-time" style="display:${query.time_preset==='custom'||(query.time_from&&!query.time_preset)?'grid':'none'}; grid-template-columns:1fr 1fr; gap:8px;"><div class="field"><label for="filter-time-from">Dari</label><input class="input" type="datetime-local" id="filter-time-from" name="time_from" value="${esc(query.time_from)}"></div><div class="field"><label for="filter-time-to">Sampai</label><input class="input" type="datetime-local" id="filter-time-to" name="time_to" value="${esc(query.time_to)}"></div></div><div class="field"><label for="filter-sort">Urutan</label><select id="filter-sort" name="ordering"><option value="timestamp:desc">Terbaru</option><option value="timestamp:asc">Kronologis</option><option value="severity:desc">Severity tertinggi</option><option value="hits:desc">Hits terbanyak</option></select></div><p class="meta">Tenant mengikuti workspace. Pilihan alert tetap tersimpan saat filter berubah.</p><div class="dialog-actions"><button type="button" class="button" data-action="reset">Reset filter</button><button class="button primary" type="submit">Terapkan</button></div></form></dialog>
    <dialog class="app-dialog" id="batch-add-incident-dialog" aria-labelledby="batch-incident-title"><div class="dialog-header"><h2 id="batch-incident-title">Masukkan Bukti ke Insiden</h2><button class="button icon-button" data-close-batch-incident aria-label="Tutup dialog">${icon('close')}</button></div><form id="batch-add-incident-form" class="stack"><p class="muted"><span id="batch-incident-count">0</span> alert terpilih akan ditautkan ke kasus insiden di bawah ini.</p><div class="field"><label for="batch-incident-select">Pilih Insiden Sasaran</label><select class="select" id="batch-incident-select" name="group_id" required><option value="">Memuat daftar insiden…</option></select></div><div class="dialog-actions" style="margin-top:20px; display:flex; justify-content:flex-end; gap:8px;"><button type="button" class="button" data-close-batch-incident>Batal</button><button class="button primary" type="submit">Tautkan ke Insiden</button></div></form></dialog>`;
  const results = root.querySelector('#queue-results'), inspector = root.querySelector('#alert-inspector');
  const workspace = root.querySelector('#triage-workspace');
  const dialog = root.querySelector('#triage-filter-dialog');
  root.querySelector('#triage-sort').value = `${query.sort_by}:${query.sort}`;
  root.querySelector('#filter-sort').value = `${query.sort_by}:${query.sort}`;
  root.querySelector('#filter-membership').value = query.status;
  const on = (el,type,fn) => el.addEventListener(type,fn,{signal});
  function updateQuery(changes, {replace=false}={}) {
    const p = new URLSearchParams(route.params);
    for (const [k,v] of Object.entries(changes)) v===null||v===''?p.delete(k):p.set(k,String(v));
    if (!Object.hasOwn(changes,'offset')) p.delete('offset');
    p.delete('alert');
    navigate(withParams('/triage',p),{replace});
  }
  function report(ids) {
    const p=scopeParams(query,ids?.length?{ids}:{});
    navigate(withParams('/reports',p));
  }
  async function copySelectedLogs(redacted = false, defanged = false) {
    const ids = selection.ids();
    if (!ids.length) return;
    notify(`Mengambil full log untuk ${ids.length} alert…`, 'info');
    try {
      const itemsList = await Promise.all(ids.map(async id => {
        let item = items.find(a => a.id === id);
        if (!item || !item.full_log) {
          try {
            item = await json(apiURL(`/api/alerts/${id}`, {tenant}), {signal});
          } catch {
            return {id, rule_id: '99999', is_error: true};
          }
        }
        return item;
      }));
      itemsList.sort((a, b) => {
        const rA = String(a.rule_id || '');
        const rB = String(b.rule_id || '');
        if (rA !== rB) return rA.localeCompare(rB);
        return String(a.timestamp || '').localeCompare(String(b.timestamp || ''));
      });
      const logs = itemsList.map(item => {
        if (item.is_error) return `[Alert #${item.id}] Gagal memuat log.`;
        const time = item.timestamp ? formatTime(item.timestamp) : '—';
        const rawLog = item.full_log || item.raw?.full_log || (item.raw ? JSON.stringify(item.raw, null, 2) : 'Tidak ada log.');
        return `================================================================================
Alert #${item.alert_id || item.id} · ${item.description || 'Alert'}
Waktu: ${time} | Rule: ${item.rule_id || '—'} (Level ${item.rule_level ?? 0})
Target Asset: ${item.agent_name || '—'} (${item.agent_ip || '—'}) | Source IP: ${item.source_ip || '—'}
--------------------------------------------------------------------------------
${rawLog}`;
      });
      let fullText = logs.join('\n\n');
      if (redacted) {
        const d = await json('/api/sanitize-logs', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({text: fullText}),
          signal,
        });
        fullText = d.sanitized;
      } else if (defanged) {
        fullText = defangText(fullText);
      }
      await copyText(fullText);
      notify(`${ids.length} full log alert terpilih berhasil disalin.`, 'success');
    } catch (err) {
      if (err.name !== 'AbortError') notify(`Gagal menyalin log: ${err.message}`, 'error');
    }
  }

  function syncSelection() {
    const ids=selection.ids();
    root.querySelectorAll('[data-select]').forEach(el=>{el.checked=selection.has(Number(el.dataset.select));});
    root.querySelectorAll('[data-row]').forEach(el=>{const selected=selection.has(Number(el.dataset.row));el.setAttribute('aria-selected',String(selected));el.classList.toggle('is-selected',selected);});
    const visible=items.filter(a=>selection.has(a.id)).length;
    root.querySelectorAll('[data-select-page]').forEach(el=>{el.checked=!!items.length&&visible===items.length;el.indeterminate=visible>0&&visible<items.length;});
    const slot=root.querySelector('#selection-actions');
    slot.innerHTML=ids.length?`<div class="selection-toolbar" aria-label="Tindakan pilihan"><strong>${ids.length.toLocaleString('id-ID')} alert dipilih</strong><button class="button primary" data-action="create-incident">${icon('plus')}Buat insiden</button><button class="button" data-action="add-selected-to-incident">${icon('cases')}Masukkan ke insiden</button><button class="button" data-action="batch-enrich-intel">${icon('refresh')}Live Enrich IP</button><button class="button" data-action="copy-selected-logs">${icon('copy')}Salin log</button><button class="button" data-action="copy-selected-redacted">Tersamarkan</button><button class="button" data-action="batch-review">Tandai direview</button><button class="button" data-action="batch-unreview">Belum direview</button><button class="button" data-action="report-selected">Laporan</button><button class="button icon-button" data-action="clear-selection" aria-label="Batalkan pilihan">${icon('close')}</button>${ids.length>visible?`<span class="selection-note">${ids.length-visible} pilihan berada di luar halaman/filter ini. Tindakan memakai seluruh pilihan pada tenant ini.</span>`:''}</div>`:'';
  }
  function renderResults() {
    if (!items.length) results.innerHTML=emptyState('Tidak ada alert pada antrean ini',query.q||query.filter_preset||query.group_id||query.review_status!=='all'?'Coba reset filter atau lihat antrean Semua. Pilihan sebelumnya tetap tersimpan.':'Impor export Wazuh untuk memulai triage.',`<button class="button" data-action="reset">Reset filter</button><a class="button primary" href="${scopedRoute('/imports')}">Impor alert</a>`);
    else results.innerHTML=renderQueue(items,{selectedIds:selection.ids(),activeId,query,showIntel,showAllLogs,expandedLogIds,wrapLog});
    const standardSizes = [25, 50, 100, 200, 500, 1000];
    const isCustom = !standardSizes.includes(query.limit);
    const pageSizeOptions = standardSizes.map(n => `<option value="${n}" ${query.limit === n ? 'selected' : ''}>${n} per halaman</option>`).join('');
    root.querySelector('#queue-pagination').innerHTML=`<div class="pagination-info" style="display:flex; align-items:center; gap:12px; flex-wrap:wrap;"><span>${total?`${(query.offset+1).toLocaleString('id-ID')}–${Math.min(query.offset+items.length,total).toLocaleString('id-ID')}`:'0'} dari ${total.toLocaleString('id-ID')} alert</span><label class="page-size-label" style="display:inline-flex; align-items:center; gap:6px;"><span class="sr-only">Jumlah per halaman</span><select class="select page-size-select" id="page-size-select" style="padding:2px 8px; min-height:30px; font-size:12px;">${pageSizeOptions}<option value="custom" ${isCustom ? 'selected' : ''}>${isCustom ? `Kustom (${query.limit})` : 'Kustom…'}</option></select></label><div id="custom-limit-wrap" style="display:${isCustom ? 'inline-flex' : 'none'}; gap:4px; align-items:center;"><input type="number" id="custom-limit-input" min="1" max="10000" value="${query.limit}" style="width:75px; min-height:28px; padding:2px 6px; font-size:12px;" class="input mono" placeholder="Jml"><button type="button" class="button" id="btn-apply-custom-limit" style="min-height:28px; padding:2px 8px; font-size:12px;">Terapkan</button></div></div><div class="pagination-actions"><button class="button" data-page="previous" ${query.offset===0?'disabled':''}>Sebelumnya</button><button class="button" data-page="next" ${query.offset+items.length>=total?'disabled':''}>Berikutnya</button></div>`;
    syncSelection();
  }
  async function loadSummary() {
    summaryRequest?.abort();
    summaryRequest = new AbortController();
    const summarySlot = root.querySelector('#triage-summary-slot');
    if (!summarySlot) return;
    try {
      const sParams = summaryRequestParams(query);
      const sData = await json(apiURL('/api/triage/summary', sParams), {signal: summaryRequest.signal});
      if (signal.aborted) return;
      summaryData = sData;
      summarySlot.innerHTML = renderTriageSummary(summaryData, query, {collapsed: isSummaryCollapsed});
    } catch (e) {
      if (e.name !== 'AbortError' && !signal.aborted) {
        summarySlot.innerHTML = '';
      }
    }
  }
  async function load() {
    loadSummary();
    pageRequest?.abort();pageRequest=new AbortController();const version=++generation;
    const abort=()=>pageRequest?.abort();signal.addEventListener('abort',abort,{once:true});
    results.setAttribute('aria-busy','true');
    try {
      const params=new URLSearchParams(route.params);
      for(const key of new Set(scopeParams(query).keys()))params.delete(key);
      for(const [key,value] of scopeParams(query))params.append(key,value);
      params.set('limit',String(query.limit));params.set('offset',String(query.offset));
      params.set('summary',String(!showAllLogs));
      const data=await json(apiURL('/api/alerts',params),{signal:pageRequest.signal});
      if(signal.aborted||version!==generation)return;
      if(!Array.isArray(data.items)||!Number.isFinite(Number(data.total)))throw new Error('Format antrean tidak valid. Coba lagi.');
      items=data.items;total=Number(data.total);renderResults();
      if(activeId)await openInspector(activeId,false);
    } catch(e) {if(e.name!=='AbortError'&&!signal.aborted)results.innerHTML=errorState(e.message);}
    finally {results.removeAttribute('aria-busy');signal.removeEventListener('abort',abort);}
  }
  function setInspectorURL(id) {
    const p=new URLSearchParams(route.params);id?p.set('alert',id):p.delete('alert');
    history.replaceState(null,'',withParams('/triage',p));
    window.dispatchEvent(new Event('arbiter:route-replaced'));
  }
  function closeInspector() {
    const old=activeId;const scroll=session.close();activeId=null;currentAlert=null;detailRequest?.abort();inspector.hidden=true;workspace.classList.remove('has-inspector');setInspectorURL(null);renderResults();
    requestAnimationFrame(()=>{window.scrollTo(0,scroll);root.querySelector(`[data-inspect="${Number(old)}"]`)?.focus({preventScroll:true});});
  }
  function inspectorBody(a) {
    if(activeTab==='log'){
      const log=a.full_log||a.raw?.full_log||'Log tidak tersedia untuk alert ini.';
      return `<div class="split"><h3>Log Lengkap</h3><div class="page-actions"><button class="button" data-action="copy-raw-log">${icon('copy')}Salin log</button><button class="button" data-action="copy-redacted">Versi tersamarkan</button><button class="button" data-action="copy-defanged">Salin defanged</button><button class="button" data-action="toggle-wrap">${wrapLog?'Unwrap':'Wrap'}</button></div></div><pre class="raw-log ${wrapLog?'':'no-wrap'}">${esc(log)}</pre>${a.previous_output?`<details><summary>Previous output</summary><pre class="raw-log">${esc(a.previous_output)}</pre></details>`:''}<p class="meta">Redaksi otomatis menyamarkan IP dan rahasia sensitif sebelum dibagikan.</p>`;
    }
    if(activeTab==='raw')return `<div class="split"><h3>Raw alert JSON</h3><button class="button" data-action="copy-raw">${icon('copy')}Salin raw</button></div><p class="warning-copy">Konten mentah dapat memuat informasi sensitif. Tinjau sebelum dibagikan.</p><pre class="raw-log">${esc(JSON.stringify(a.raw||{},null,2))}</pre>`;
    if(activeTab==='occurrences')return `<div class="split"><h3>Kejadian berulang</h3><span class="meta num">${Number(a.hit_count)||1} hits</span></div><dl class="detail-grid"><div class="key-value"><dt>Pertama</dt><dd>${esc(formatTime(a.first_seen||a.timestamp))}</dd></div><div class="key-value"><dt>Terakhir</dt><dd>${esc(formatTime(a.last_seen||a.timestamp))}</dd></div></dl><ol class="timeline">${(a.duplicate_instances?.length?a.duplicate_instances:[{timestamp:a.timestamp,id:a.alert_id}]).map(inst=>`<li><time>${esc(formatTime(inst.timestamp))}</time><span class="meta mono">${esc(inst.id||'—')}</span>${inst.full_log?`<details><summary>Log kejadian</summary><pre class="raw-log">${esc(inst.full_log)}</pre></details>`:''}</li>`).join('')}</ol>`;
    const log=a.full_log||a.raw?.full_log;
    return `<dl class="detail-grid"><div class="key-value"><dt>Target asset</dt><dd>${esc(a.agent_name||'—')}</dd></div><div class="key-value"><dt>Tenant</dt><dd>${esc(a.tenant||'Default')}</dd></div><div class="key-value"><dt>Detection rule</dt><dd>${esc(a.rule_id||'—')} · Level ${Number(a.rule_level)||0}</dd></div><div class="key-value"><dt>Waktu</dt><dd>${esc(formatTime(a.timestamp))}</dd></div><div class="key-value wide"><dt>Source / intel</dt><dd class="mono">${esc(a.source_ip||'—')}</dd><dd class="meta" style="margin-top:2px;">${intelBadge(a)}</dd>${a.source_ip?`<dd style="display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-top:8px;"><button class="button" data-action="enrich-single-ip" data-ip="${esc(a.source_ip)}">${icon('refresh')}Live Enrich</button><a class="button" href="http://localhost:3001/ip/${encodeURIComponent(a.source_ip)}" rel="noopener noreferrer" target="_blank">Buka IP Intel ${icon('external')}</a></dd>`:''}</div>${a.cve?`<div class="key-value"><dt>CVE</dt><dd>${esc(a.cve)}</dd></div>`:''}${a.mitre_ids?.length?`<div class="key-value wide"><dt>MITRE</dt><dd>${esc(a.mitre_ids.join(', '))}</dd></div>`:''}</dl>${classificationBlock(a)}${log?`<section class="stack"><div class="split"><h3>Log utama</h3><button class="button" data-action="copy-redacted">Versi tersamarkan</button></div><pre class="raw-log">${esc(log)}</pre><p class="meta">Redaksi otomatis bukan jaminan aman untuk cloud. Tinjau hasil sebelum membagikan.</p></section>`:''}${a.previous_output?`<details><summary>Previous output</summary><pre class="raw-log">${esc(a.previous_output)}</pre></details>`:''}<section class="stack"><h3>Insiden terkait</h3>${a.groups?.length?a.groups.map(g=>`<div class="split"><a href="${scopedRoute('/incidents/'+encodeURIComponent(g.id))}">${esc(g.title)}</a><button class="button icon-button" data-remove-group="${esc(g.id)}" aria-label="Keluarkan dari insiden ${esc(g.title)}">${icon('close')}</button></div>`).join(''):'<p class="meta">Belum terhubung ke insiden.</p>'}<div class="field"><label for="inspector-group">Tambahkan ke insiden</label><select id="inspector-group" name="group_id"><option value="">Memuat insiden…</option></select></div><button class="button" data-action="add-group">Tambahkan bukti ke insiden</button></section><section class="stack"><h3>Review</h3><div class="split"><span class="meta">${a.is_reviewed?'Sudah ditinjau':'Belum ditinjau'}</span><button class="button" data-action="review-current">${a.is_reviewed?'Kembalikan ke antrean':'Tandai selesai ditinjau'}</button></div></section>`;
  }
  async function renderInspector() {
    const a=currentAlert;if(!a)return;
    inspector.innerHTML=`<div class="inspector-head"><div class="inspector-title">${severity(a.rule_level)}<h2 tabindex="-1" id="inspector-title">${esc(a.description||'Detail alert')}</h2><span class="meta mono">${esc(a.alert_id||a.id)}</span></div><button class="button icon-button" data-action="close-inspector" aria-label="Tutup detail dan kembali ke antrean">${icon('close')}</button></div><div class="tabs inspector-tabs" aria-label="Bagian detail">${[['detail','Detail'],['log','Log'],['occurrences','Kejadian'],['raw','Raw JSON']].map(([k,l])=>`<button class="tab" data-detail-tab="${k}" aria-pressed="${activeTab===k}">${l}</button>`).join('')}</div><div class="inspector-content">${inspectorBody(a)}</div>`;
    if(activeTab==='detail')try{
      const groups=await json(apiURL('/api/groups',{tenant}),{signal});
      const select=root.querySelector('#inspector-group');if(select)select.innerHTML='<option value="">Pilih insiden…</option>'+groups.filter(g=>!a.groups?.some(link=>link.id===g.id)).map(g=>`<option value="${esc(g.id)}">${esc(g.title)}</option>`).join('');
    }catch(e){if(e.name!=='AbortError'){const select=root.querySelector('#inspector-group');if(select)select.innerHTML='<option value="">Tidak dapat memuat insiden</option>';}}
  }
  async function openInspector(id,focus=true) {
    if(!session.activeId())session.rememberQueue(window.scrollY);session.open(id);const detailVersion=session.nextDetail();
    activeId=Number(id);detailRequest?.abort();detailRequest=new AbortController();
    inspector.hidden=false;workspace.classList.add('has-inspector');inspector.innerHTML=loadingRows(3);setInspectorURL(activeId);
    try{
      const a=await json(apiURL(`/api/alerts/${activeId}`,{tenant}),{signal:detailRequest.signal});if(signal.aborted||!session.isCurrentDetail(detailVersion)||Number(a.id)!==activeId)return;
      currentAlert=a;await renderInspector();renderResults();if(focus)root.querySelector('#inspector-title')?.focus({preventScroll:true});
    }catch(e){if(e.name!=='AbortError'&&!signal.aborted&&session.isCurrentDetail(detailVersion))inspector.innerHTML=`<div class="inspector-content">${errorState(e.message)}<button class="button" data-action="close-inspector">Kembali ke antrean</button></div>`;}
  }
  async function batch(reviewed,ids=selection.ids()) {
    if(!ids.length)return;
    try{await json(apiURL('/api/alerts/batch-review',{tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_ids:ids,is_reviewed:reviewed}),signal});notify(reviewed?'Alert ditandai direview.':'Alert dikembalikan ke antrean.','success');await load();}
    catch(e){if(e.name!=='AbortError')notify(e.message,'error');}
  }
  async function correlation(){
    const slot=root.querySelector('#correlation-slot');slot.innerHTML=`<div class="correlation-panel">${loadingRows(2)}</div>`;
    try{
      const d=await json(apiURL('/api/suggestions',scopeParams(query)),{signal});
      const cards=d.suggestions?.length?d.suggestions.map((g,i)=>{
        const count=Number(g.alert_count||(g.alert_ids||[]).length||0);
        const sevBadge=g.rule_level!==undefined?severity(g.rule_level):'';
        const ips=Array.isArray(g.source_ips)&&g.source_ips.length?`<span class="meta">Source IP: <strong class="mono">${esc(g.source_ips.slice(0,3).join(', '))}${g.source_ips.length>3?` (+${g.source_ips.length-3})`:''}</strong></span>`:'';
        const agent=g.agent_name?`<span class="meta">Host / Agent: <strong>${esc(g.agent_name)}</strong></span>`:'';
        const ruleInfo=g.rule_id&&g.rule_id!=='-'?`<span class="meta">Rule: <strong>${esc(g.rule_id)}</strong></span>`:'';
        const basis=g.basis||g.category?`<span class="correlation-basis-badge">${esc(g.basis||g.category)}</span>`:'';
        const verdict=g.verdict&&verdictLabels[g.verdict]?`<span class="badge ${verdictClass(g.verdict)}">${esc(verdictLabels[g.verdict])}</span>`:'';
        const response=g.response_alert_count?`<span class="meta">${Number(g.response_alert_count)} respons tertaut</span>`:'';
        return `<article class="correlation-card" data-suggestion-card="${i}">
          <div class="correlation-head">
            <div class="correlation-title-row">
              ${sevBadge}
              <strong class="correlation-title">${esc(g.title||g.category||'Saran insiden')}</strong>
              <span class="meta num">${count} alert (${g.total_hits||count} hits)</span>
            </div>
            <button class="button primary" data-suggestion="${i}">Tinjau sebagai insiden (${count} bukti)</button>
          </div>
          <div class="correlation-meta meta">
            ${verdict}
            ${basis}
            ${agent}
            ${ips}
            ${ruleInfo}
            ${response}
          </div>
          <p class="correlation-reason">${esc(g.reason||g.analysis||'Tinjau bukti sebelum membuat insiden.')}</p>
          ${chainLine(g)}
        </article>`;
      }).join(''):'<p class="meta">Tidak ada saran korelasi pada scope ini.</p>';

      slot.innerHTML=`<section class="correlation-panel stack"><div class="split"><h2>Korelasi lokal</h2><button class="button icon-button" data-action="close-correlation" aria-label="Tutup korelasi">${icon('close')}</button></div><p class="meta">${esc(d.warning||'Saran berdasarkan rule lokal, bukan keputusan investigasi.')}</p><div class="correlation-grid">${cards}</div></section>`;
      slot._suggestions=d.suggestions||[];
    }
    catch(e){if(e.name!=='AbortError')slot.innerHTML=errorState(e.message);}
  }
  on(root,'click',async e=>{
    const button=e.target.closest('button');if(!button)return;
    if(button.dataset.summaryAction==='severity'){updateQuery({facet:'severity',facet_value:button.dataset.severity,offset:0});return;}
    if(button.dataset.summaryAction==='top-rule'){updateQuery({facet:'rule_id',facet_value:button.dataset.ruleId,offset:0});return;}
    if(button.dataset.summaryAction==='grouped'){updateQuery({status:'grouped',offset:0});return;}
    if(button.dataset.summaryAction==='pivot-ip'){const p=summaryRequestParams(query);p.set('pivot_by','source_ip');navigate(withParams('/stats',p));return;}
    if(button.dataset.summaryAction==='pivot-agent'){const p=summaryRequestParams(query);p.set('pivot_by','agent');navigate(withParams('/stats',p));return;}
    if(button.dataset.action==='toggle-summary'){
      isSummaryCollapsed=!isSummaryCollapsed;
      const p=new URLSearchParams(route.params);
      if(isSummaryCollapsed)p.set('summary','collapsed');else p.delete('summary');
      history.replaceState(null,'',withParams('/triage',p));
      const summarySlot=root.querySelector('#triage-summary-slot');
      if(summarySlot&&summaryData)summarySlot.innerHTML=renderTriageSummary(summaryData,query,{collapsed:isSummaryCollapsed});
      return;
    }
    if(button.dataset.action==='clear-facet'){updateQuery({facet:null,facet_value:null,offset:0});return;}
    if(button.dataset.action==='clear-alert-ids'){updateQuery({alert_ids:null,offset:0});return;}
    if(button.dataset.review){updateQuery({review_status:button.dataset.review});return;}
    if(button.dataset.sort){updateQuery({sort_by:button.dataset.sort,sort:query.sort_by===button.dataset.sort&&query.sort==='desc'?'asc':'desc'});return;}
    if(button.dataset.inspect){activeTab=button.dataset.inspectTab||'detail';await openInspector(button.dataset.inspect);return;}
    if(button.dataset.detailTab){activeTab=button.dataset.detailTab;await renderInspector();return;}
    if(button.dataset.page){updateQuery({offset:button.dataset.page==='next'?query.offset+query.limit:Math.max(0,query.offset-query.limit)});return;}
    if(button.hasAttribute('data-close-filter')){dialog.close();return;}
    if(button.hasAttribute('data-close-batch-incident')){root.querySelector('#batch-add-incident-dialog')?.close();return;}
    if(button.dataset.removeGroup){try{await json(apiURL(`/api/groups/${encodeURIComponent(button.dataset.removeGroup)}/members/${currentAlert.id}`,{tenant}),{method:'DELETE',signal});await openInspector(currentAlert.id,false);notify('Bukti dikeluarkan dari insiden.','success');}catch(err){if(err.name!=='AbortError')notify(err.message,'error');}return;}
    if(button.dataset.suggestion){const g=root.querySelector('#correlation-slot')._suggestions[Number(button.dataset.suggestion)];const ids=(g.alert_pks||g.alert_ids||[]).map(Number).filter(Number.isSafeInteger);if(ids.length)navigate(scopedRoute('/incidents/new',{alert_ids:ids.join(',')}));else notify('Saran tidak memiliki ID bukti yang valid. Pilih bukti dari antrean.','error');return;}
    const action=button.dataset.action;
    if(action==='filters'){dialog.showModal();return;}
    if(action==='more'){const opts=root.querySelector('#queue-options');opts.hidden=!opts.hidden;button.setAttribute('aria-expanded',String(!opts.hidden));return;}
    if(action==='reset'){dialog.close();navigate(scopedRoute('/triage',{review_status:'all'}));return;}
    if(action==='retry'){if(button.closest('#alert-inspector'))openInspector(activeId);else load();return;}
    if(action==='close-inspector'){closeInspector();return;}
    if(action==='clear-selection'){selection.clear();syncSelection();return;}
    if(action==='add-selected-to-incident'){
      const ids=selection.ids();
      if(!ids.length){notify('Pilih minimal satu alert terlebih dahulu.','error');return;}
      const batchDialog=root.querySelector('#batch-add-incident-dialog');
      const countSpan=root.querySelector('#batch-incident-count');
      const select=root.querySelector('#batch-incident-select');
      if(countSpan)countSpan.textContent=ids.length.toLocaleString('id-ID');
      if(select)select.innerHTML='<option value="">Memuat daftar insiden…</option>';
      batchDialog?.showModal();
      try{
        const groups=await json(apiURL('/api/groups',{tenant}),{signal});
        if(select){
          if(!groups.length){
            select.innerHTML='<option value="">Belum ada kasus insiden pada tenant ini</option>';
          }else{
            select.innerHTML='<option value="">Pilih insiden sasaran…</option>'+groups.map(g=>`<option value="${esc(g.id)}">${esc(g.title)} (${g.alert_count??g.alert_pks?.length??0} bukti)</option>`).join('');
          }
        }
      }catch(err){
        if(err.name!=='AbortError'&&select)select.innerHTML='<option value="">Gagal memuat insiden</option>';
      }
      return;
    }
    if(action==='copy-selected-logs'||action==='copy-selected-redacted'){button.disabled=true;await copySelectedLogs(action==='copy-selected-redacted',false);button.disabled=false;return;}
    if(action==='toggle-all-queue-logs'){showAllLogs=!showAllLogs;const btn=root.querySelector('#btn-toggle-queue-logs');if(btn){btn.setAttribute('aria-pressed',String(showAllLogs));btn.classList.toggle('is-active',showAllLogs);btn.innerHTML=`${icon('cases')} <span class="btn-text">${showAllLogs?'Tutup semua log':'Munculkan semua log'}</span>`;}await load();return;}
    if(action==='toggle-row-log'){const aid=Number(button.dataset.alertId);if(expandedLogIds.has(aid)){expandedLogIds.delete(aid);renderResults();}else{expandedLogIds.add(aid);const item=items.find(a=>a.id===aid);if(item&&!item.full_log){json(apiURL(`/api/alerts/${aid}`,{tenant}),{signal}).then(detail=>{if(detail?.full_log||detail?.raw?.full_log){item.full_log=detail.full_log||detail.raw?.full_log;renderResults();}}).catch(()=>{});}renderResults();}return;}
    if(action==='copy-queue-log'||action==='copy-queue-redacted'||action==='copy-queue-defanged'){const aid=Number(button.dataset.alertId);const item=items.find(a=>a.id===aid);let text=item?.full_log||item?.raw?.full_log||'';if(!text){notify('Log tidak tersedia.','error');return;}if(action==='copy-queue-redacted'){try{const d=await json('/api/sanitize-logs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text}),signal});await copyText(d.sanitized);notify('Versi tersamarkan disalin.','info');}catch{notify('Gagal menyalin versi tersamarkan.','error');}}else if(action==='copy-queue-defanged'){await copyText(defangText(text));notify('Versi defanged disalin (aman dibagikan).','info');}else{await copyText(text);notify('Log alert disalin.','info');}return;}
    if(action==='report-query'){report();return;}
    if(action==='report-selected'){report(selection.ids());return;}
    if(action==='enrich-single-ip'){
      const ip=button.dataset.ip;if(!ip)return;
      button.disabled=true;button.textContent='Enriching…';
      try{
        const res=await json(apiURL('/api/intel/enrich',{tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips:[ip]}),signal});
        const item=res.enriched?.[0];
        notify(`IP ${ip} di-enrich: Skor Abuse ${item?.abuse_score??0}% (${item?.isp||item?.status||'ok'}).`,'success');
        await load();if(activeId)await openInspector(activeId,false);
      }catch(err){if(err.name!=='AbortError')notify(err.message,'error');}
      finally{if(button.isConnected){button.disabled=false;button.innerHTML=`${icon('refresh')}Live Enrich`;}}
      return;
    }
    if(action==='batch-enrich-intel'){
      const ids=selection.ids();if(!ids.length){notify('Pilih minimal satu alert terlebih dahulu.','error');return;}
      button.disabled=true;button.textContent='Enriching…';
      try{
        const res=await json(apiURL('/api/intel/enrich',{tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_ids:ids}),signal});
        notify(`${res.count||0} IP unik dari ${ids.length} alert berhasil di-enrich.`,'success');
        await load();if(activeId)await openInspector(activeId,false);
      }catch(err){if(err.name!=='AbortError')notify(err.message,'error');}
      finally{if(button.isConnected){button.disabled=false;button.innerHTML=`${icon('refresh')}Live Enrich IP`;}}
      return;
    }
    if(action==='create-incident'||action==='create-current'){const ids=action==='create-current'?[currentAlert.id]:selection.ids();navigate(scopedRoute('/incidents/new',{alert_ids:ids.join(',')}));return;}
    if(action==='batch-review'||action==='batch-unreview'||action==='review-current'){button.disabled=true;await batch(action==='review-current'?!currentAlert.is_reviewed:action==='batch-review',action==='review-current'?[currentAlert.id]:selection.ids());if(button.isConnected)button.disabled=false;return;}
    if(action==='add-group'){const id=root.querySelector('#inspector-group').value;if(!id){notify('Pilih insiden terlebih dahulu.','error');return;}button.disabled=true;try{await json(apiURL(`/api/groups/${encodeURIComponent(id)}/members`,{tenant}),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_pks:[currentAlert.id]}),signal});await openInspector(currentAlert.id,false);notify('Bukti ditambahkan ke insiden.','success');}catch(err){if(err.name!=='AbortError')notify(err.message,'error');}finally{button.disabled=false;}return;}
    if(action==='copy-raw'||action==='copy-redacted'||action==='copy-raw-log'||action==='copy-defanged'){button.disabled=true;try{let text=action==='copy-raw'?JSON.stringify(currentAlert.raw||{},null,2):currentAlert.full_log||currentAlert.raw?.full_log||'';if(action==='copy-redacted'){const d=await json('/api/sanitize-logs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text}),signal});text=d.sanitized;await copyText(text);notify('Versi tersamarkan disalin. Tinjau sebelum dibagikan.','info');}else if(action==='copy-defanged'){text=defangText(text);await copyText(text);notify('Versi defanged disalin (aman dibagikan).','info');}else if(action==='copy-raw-log'){await copyText(text);notify('Log lengkap disalin.','info');}else{await copyText(text);notify('Raw JSON disalin. Berisi data sensitif.','info');}}catch(err){if(err.name!=='AbortError')notify('Gagal menyalin. Clipboard tidak diizinkan; salin manual dari panel.','error');}finally{button.disabled=false;}return;}
    if(action==='toggle-wrap'){wrapLog=!wrapLog;renderInspector();return;}
    if(action==='correlation'){correlation();return;}
    if(action==='close-correlation')root.querySelector('#correlation-slot').innerHTML='';
  });
  on(root,'change',e=>{
    const el=e.target;
    if(el.matches('[data-select]')){const id=Number(el.dataset.select);if(el._shift&&lastSelected!==null)selection.selectRange(items.map(a=>a.id),lastSelected,id,el.checked);else selection.toggle(id,el.checked);lastSelected=id;syncSelection();}
    if(el.matches('[data-select-page]')){items.forEach(a=>selection.toggle(a.id,el.checked));syncSelection();}
    if(el.id==='triage-sort'){const [sort_by,sort]=el.value.split(':');updateQuery({sort_by,sort});}
    if(el.id==='show-intel'){showIntel=el.checked;renderResults();}
    if(el.id==='filter-time-preset'){const custom=root.querySelector('#filter-custom-time');if(custom)custom.style.display=el.value==='custom'?'grid':'none';}
    if(el.id==='page-size-select'){
      if(el.value==='custom'){
        const wrap=root.querySelector('#custom-limit-wrap');
        if(wrap){
          wrap.style.display='inline-flex';
          const input=root.querySelector('#custom-limit-input');
          input?.focus();
          input?.select();
        }
      }else{
        const wrap=root.querySelector('#custom-limit-wrap');
        if(wrap)wrap.style.display='none';
        updateQuery({limit:Number(el.value),offset:0});
      }
    }
  });
  on(root,'click',e=>{
    if(e.target.id==='btn-apply-custom-limit'||e.target.closest('#btn-apply-custom-limit')){
      const input=root.querySelector('#custom-limit-input');
      const val=Math.min(10000,Math.max(1,parseInt(input?.value,10)||50));
      updateQuery({limit:val,offset:0});
      return;
    }
    if(e.target.matches('[data-select]'))e.target._shift=e.shiftKey;
  });
  on(root,'keydown',e=>{
    if(e.target.id==='custom-limit-input'&&e.key==='Enter'){
      e.preventDefault();
      const val=Math.min(10000,Math.max(1,parseInt(e.target.value,10)||50));
      updateQuery({limit:val,offset:0});
    }
  });
  on(root.querySelector('#triage-search'),'input',e=>{clearTimeout(searchTimer);const q=e.target.value;searchTimer=setTimeout(()=>updateQuery({q},{replace:true}),350);});
  on(root.querySelector('#triage-filter-form'),'submit',e=>{
    e.preventDefault();const form=new FormData(e.target);const [sort_by,sort]=form.get('ordering').split(':');dialog.close();
    const preset=form.get('time_preset')||'';let time_from=form.get('time_from')||'',time_to=form.get('time_to')||'';
    if(preset&&preset!=='custom'){const ms={'1h':3600000,'24h':86400000,'7d':604800000,'30d':2592000000}[preset];if(ms)time_from=new Date(Date.now()-ms).toISOString();}
    else if(time_from){try{time_from=new Date(time_from).toISOString();}catch{}}
    if(time_to){try{time_to=new Date(time_to).toISOString();}catch{}}
    updateQuery({filter_preset:form.get('filter_preset'),status:form.get('status'),time_preset:preset,time_from,time_to,sort_by,sort});
  });
  on(root.querySelector('#batch-add-incident-form'),'submit',async e=>{
    e.preventDefault();const form=new FormData(e.target);const groupId=form.get('group_id');
    const batchDialog=root.querySelector('#batch-add-incident-dialog');
    if(!groupId){notify('Pilih insiden terlebih dahulu.','error');return;}
    const ids=selection.ids();if(!ids.length){batchDialog?.close();notify('Tidak ada alert yang dipilih.','error');return;}
    const submitBtn=e.target.querySelector('button[type=submit]');if(submitBtn)submitBtn.disabled=true;
    try{
      await json(apiURL(`/api/groups/${encodeURIComponent(groupId)}/members`,{tenant}),{
        method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({alert_pks:ids}),signal
      });
      batchDialog?.close();selection.clear();syncSelection();notify(`${ids.length} alert berhasil ditautkan ke kasus insiden.`,'success');await load();
    }catch(err){if(err.name!=='AbortError')notify(err.message,'error');}finally{if(submitBtn)submitBtn.disabled=false;}
  });
  on(root,'keydown',e=>{if(e.key==='Escape'&&activeId&&!dialog.open){e.preventDefault();closeInspector();}});
  on(root,'arbiter:refresh',()=>load());
  const filters=[];if(query.q)filters.push(`Pencarian: ${esc(query.q)}`);if(query.filter_preset)filters.push(esc(presets.find(([v])=>v===query.filter_preset)?.[1]));if(query.group_id)filters.push('Bukti insiden terpilih');if(query.alert_ids){const aidCount=query.alert_ids.split(',').filter(Boolean).length;filters.push(`Alert terkait (${aidCount}) <button class="button text-button" data-action="clear-alert-ids" style="cursor:pointer; padding:0 4px;" aria-label="Tampilkan semua alert">✕</button>`);}if(query.status!=='all')filters.push(query.status==='grouped'?'Sudah masuk insiden':'Belum masuk insiden');
  if(query.facet&&query.facet_value)filters.push(`Filter: ${esc(query.facet)} = ${esc(query.facet_value)} <button class="button text-button" data-action="clear-facet" style="cursor:pointer; padding:0 4px;">✕</button>`);
  if(query.time_preset){const labels={'1h':'1 jam terakhir','24h':'24 jam terakhir','7d':'7 hari terakhir','30d':'30 hari terakhir'};filters.push(labels[query.time_preset]||`Waktu: ${esc(query.time_preset)}`);}
  else if(query.time_from||query.time_to)filters.push(`Waktu: ${query.time_from?esc(formatTime(query.time_from)):'—'} s/d ${query.time_to?esc(formatTime(query.time_to)):'kini'}`);
  root.querySelector('#applied-filters').innerHTML=filters.length?`${filters.map(f=>`<span>${f}</span>`).join('')}<button class="button" data-action="reset">Reset</button>`:'';
  load();
  return ()=>{session.dispose();root.classList.remove('triage-page');clearTimeout(searchTimer);pageRequest?.abort();summaryRequest?.abort();detailRequest?.abort();dialog.close();root.querySelector('#batch-add-incident-dialog')?.close();};
}
