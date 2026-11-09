import {createRouter, withParams} from './router.js';
import {importFeature} from './feature-loader.js';
import {json} from './api/client.js';
import {createSelection} from './state/selection.js';
import {probeConnection} from './state/workspace.js';
import {createNavigationMemory} from './state/navigation.js';
import {normalizeSidebarState,readSidebarState,writeSidebarState,toggleSidebarState} from './state/sidebar.js';
import {tenantScope, tenantValues} from './state/scope.js';
import {esc, icon, emptyState, errorState, loadingRows} from './ui/primitives.js';

const main=document.querySelector('#main-content');
const tenantSelect=document.querySelector('#workspace-tenant');
const tenantDialog=document.querySelector('#tenant-scope-dialog');
const tenantForm=document.querySelector('#tenant-scope-form');
const tenantOptions=document.querySelector('#tenant-scope-options');
const routeScope=params=>tenantScope(params);
const scopeParams=scope=>{const params=new URLSearchParams();for(const tenant of tenantValues(scope))params.append('tenant',tenant);return params;};
const selection=createSelection(routeScope(new URLSearchParams(location.hash.split('?')[1]||'')).key);
let currentRoute, controller, cleanup, guard=null, notifyTimer, healthPending=false, lastHealth=null, routeVersion=0;
const scrollPositions=new Map();
let navigationMemory=createNavigationMemory();
const pageTitles={triage:'Triage',stats:'Statistik',incidents:'Insiden',imports:'Impor',reports:'Laporan',realtime:'Realtime','ai-triage':'AI Triage','wazuh-queries':'Rumus Query Wazuh','error-codes':'Kamus Error Code',database:'Database',settings:'Pengaturan'};
const adminOnlyPages=new Set(['database','settings']);
let currentUser=null, authChecked=false;
for(const el of document.querySelectorAll('[data-icon]'))el.innerHTML=icon(el.dataset.icon);
document.querySelector('#open-navigation').innerHTML=icon('menu');
document.querySelector('#toggle-sidebar').innerHTML=icon('menu');
document.querySelector('#realtime-toggle').innerHTML=icon('pulse');
document.querySelector('#close-navigation').innerHTML=icon('close');
document.querySelector('#refresh-workspace').innerHTML=icon('refresh');
document.querySelector('[data-close-dialog]').innerHTML=icon('close');
for(const button of document.querySelectorAll('[data-close-tenant-scope]'))button.innerHTML=icon('close');

function notify(message,kind='info'){
  const region=document.querySelector('#notifications');clearTimeout(notifyTimer);
  region.innerHTML=`<div class="notice" data-kind="${esc(kind)}"><p>${esc(message)}</p><button class="button icon-button" aria-label="Tutup pemberitahuan">${icon('close')}</button></div>`;
  region.querySelector('button').addEventListener('click',()=>{region.innerHTML='';});
  if(kind!=='error')notifyTimer=setTimeout(()=>{region.innerHTML='';},5500);
}
function canLeave(next){
  if(guard&&!guard()&&!confirm('Ada perubahan yang belum disimpan. Tinggalkan halaman dan buang perubahan?'))return false;
  const nextScope=routeScope(next.params);
  if(selection.scope()!==nextScope.key&&selection.size()&&!confirm(`Ganti tenant dan batalkan ${selection.size()} pilihan alert?`))return false;
  selection.setScope(nextScope.key,true);return true;
}
const router=createRouter(render,canLeave);
function applyUserPermissions(){
  const isAdmin=!currentUser||currentUser.role==='admin';
  for(const link of document.querySelectorAll('.nav-link')){
    if(adminOnlyPages.has(link.dataset.page)){
      link.style.display=isAdmin?'':'none';
    }
  }
  const slot=document.querySelector('#user-session-slot');
  if(!slot)return;
  if(!currentUser){slot.innerHTML='';return;}
  const roleLabel=currentUser.role==='admin'?'Admin':'Analis';
  slot.innerHTML=`<span class="badge ${currentUser.role==='admin'?'warning':'neutral'}" title="Masuk sebagai ${esc(currentUser.display_name||currentUser.username)} (${roleLabel})">${esc(currentUser.username)} · ${roleLabel}</span><button class="button" type="button" id="logout-button" aria-label="Keluar sesi">Keluar</button>`;
  slot.querySelector('#logout-button')?.addEventListener('click',async()=>{
    try{await json('/api/auth/logout',{method:'POST'});}catch{/* ignore */}
    currentUser=null;
    renderLoginGate();
  });
}
function renderLoginGate(){
  controller?.abort();if(typeof cleanup==='function')cleanup();cleanup=null;guard=null;
  document.querySelector('#sidebar')?.setAttribute('hidden','');
  document.querySelector('.utility-bar')?.setAttribute('hidden','');
  document.title='Login — Arbiter';
  main.innerHTML=`
    <div style="max-width:420px;margin:10vh auto;padding:var(--space-5);border:1px solid var(--border-subtle);border-radius:var(--radius-md);background:var(--surface-raised, var(--bg-elevated, transparent))">
      <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-2)">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="m4 19 8-15 8 15M7 14h10M12 4v17M7 21h10"/></svg>
        <h1 style="font-size:1.35rem;margin:0">Arbiter</h1>
      </div>
      <p class="meta" style="margin-bottom:var(--space-4)">Investigation Desk — Masuk untuk mengakses workspace SOC.</p>
      <form id="login-form" class="stack" novalidate>
        <div class="field">
          <label for="login-username">Username</label>
          <input class="input mono" id="login-username" name="username" type="text" autocomplete="username" spellcheck="false" required autofocus>
        </div>
        <div class="field">
          <label for="login-password">Password</label>
          <input class="input" id="login-password" name="password" type="password" autocomplete="current-password" required>
        </div>
        <p class="inline-status" id="login-error" data-kind="error" role="alert" style="margin:0;min-height:1.25rem"></p>
        <button class="button primary" type="submit" style="width:100%;justify-content:center">${icon('shield')} Masuk ke Workspace</button>
      </form>
    </div>`;
  const form=main.querySelector('#login-form');
  form?.addEventListener('submit',async e=>{
    e.preventDefault();
    const errEl=main.querySelector('#login-error');
    const submitBtn=form.querySelector('button[type=submit]');
    const username=form.elements.username.value.trim();
    const password=form.elements.password.value;
    if(!username||!password){if(errEl)errEl.textContent='Isi username dan password.';return;}
    submitBtn.disabled=true;
    if(errEl)errEl.textContent='';
    try{
      const res=await json('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
      currentUser=res.user;
      document.querySelector('#sidebar')?.removeAttribute('hidden');
      document.querySelector('.utility-bar')?.removeAttribute('hidden');
      applyUserPermissions();
      health();tenants();loadWorkspaceSettings();
      if(currentRoute)render(currentRoute);else router.start();
    }catch(err){
      if(errEl)errEl.textContent=err.message||'Username atau password salah.';
    }finally{
      if(submitBtn.isConnected)submitBtn.disabled=false;
    }
  });
}
async function render(route){
  if(!authChecked){
    authChecked=true;
    try{
      const me=await json('/api/auth/me',{timeout:10000});
      if(me&&me.authenticated===false){currentUser=null;currentRoute=route;renderLoginGate();return;}
      currentUser=me?.user||{username:'admin',display_name:'Administrator',role:'admin'};
    }catch{
      currentUser={username:'admin',display_name:'Administrator',role:'admin'};
    }
    applyUserPermissions();
  }
  if(authChecked&&!currentUser){currentRoute=route;renderLoginGate();return;}
  const version=++routeVersion;
  const oldSearch=main.querySelector('#triage-search');
  const restoreSearch=oldSearch===document.activeElement?{start:oldSearch.selectionStart,end:oldSearch.selectionEnd}:null;
  if(currentRoute){scrollPositions.set(currentRoute.path+'?'+currentRoute.params,window.scrollY);navigationMemory.remember(currentRoute);}
  controller?.abort();if(typeof cleanup==='function')cleanup();cleanup=null;guard=null;
  controller=new AbortController();currentRoute=route;navigationMemory.remember(route);
  closeNav(false);
  const scope=routeScope(route.params);
  tenantSelect.textContent=scope.label;
  tenantSelect.title=scope.all?'Semua tenant':scope.tenants.join(', ');
  for(const link of document.querySelectorAll('.nav-link')){
    const active=link.dataset.page===route.page;
    active?link.setAttribute('aria-current','page'):link.removeAttribute('aria-current');
    link.href=navigationMemory.destination(link.dataset.page,route.params);
  }
  document.querySelector('.wordmark').href=withParams('/triage',scopeParams(scope));
  document.title=`${pageTitles[route.page]||'Halaman tidak ditemukan'} — Arbiter`;
  main.innerHTML=loadingRows();
  if(route.page==='not-found'){
    main.innerHTML=`<div class="page-header"><h1>Halaman tidak ditemukan</h1></div>${emptyState('Tujuan ini tidak tersedia','Kembali ke antrean untuk melanjutkan pekerjaan.',`<a class="button primary" href="${withParams('/triage',scopeParams(scope))}">Buka Triage</a>`)}`;return;
  }
  if(currentUser&&currentUser.role!=='admin'&&adminOnlyPages.has(route.page)){
    main.innerHTML=`<div class="page-header"><h1>${esc(pageTitles[route.page])}</h1></div>${emptyState('Akses dibatasi untuk Admin','Halaman Pengaturan dan Database hanya dapat diakses oleh akun dengan role Admin. Gunakan menu Rumus Query Wazuh atau Triage untuk operasional analis.',`<a class="button primary" href="${withParams('/triage',scopeParams(scope))}">Buka Triage</a>`)}`;return;
  }
  try{
    const feature=await importFeature(route.page);
    if(version!==routeVersion)return;
    const context={root:main,route,navigate:(...args)=>router.navigate(...args),selection,notify,databaseChanged,signal:controller.signal,setGuard:fn=>{guard=fn;}};
    const dispose=await feature.mount(context);
    if(version!==routeVersion){if(typeof dispose==='function')dispose();return;}
    cleanup=dispose;
    if(restoreSearch&&route.page==='triage'){
      const search=main.querySelector('#triage-search');search?.focus({preventScroll:true});search?.setSelectionRange(restoreSearch.start,restoreSearch.end);
    }else if(!route.params.has('alert')){
      requestAnimationFrame(()=>{main.querySelector('h1')?.setAttribute('tabindex','-1');main.querySelector('h1')?.focus({preventScroll:true});window.scrollTo(0,scrollPositions.get(route.path+'?'+route.params)||0);});
    }
  }catch(error){
    if(error.name==='AbortError'||version!==routeVersion)return;
    console.error(`[Arbiter] Gagal memuat ${route.page}:`, error);
    main.innerHTML=`<h1>${pageTitles[route.page]}</h1>${errorState('Area kerja belum dapat dimuat. Muat ulang untuk mencoba lagi.')}`;
    main.querySelector('[data-action=retry]')?.addEventListener('click',()=>render(route),{signal:controller.signal});
  }
}
async function health(force=false){
  if(healthPending||(!force&&document.hidden&&lastHealth))return;
  healthPending=true;const el=document.querySelector('#connection-state');
  try{const result=await probeConnection(()=>json('/api/health',{timeout:10000}),lastHealth);lastHealth=result.lastSuccess;el.dataset.state=result.state;el.querySelector('.connection-label').textContent=result.label;el.title=lastHealth?`${result.label} · Terakhir diperiksa ${lastHealth.toLocaleTimeString('id-ID')}`:result.label;}
  finally{healthPending=false;}
}
let tenantRows=[], databaseEpoch=0, databaseUnverified=false;
function databaseChanged(status){
  databaseEpoch++;databaseUnverified=!status;
  selection.clear();selection.setScope('all',true);
  navigationMemory=createNavigationMemory();scrollPositions.clear();
  tenantRows=status?.tenants||[];
  if(currentRoute)currentRoute.params=new URLSearchParams('tenant=all');
  history.replaceState(null,'','#/database?tenant=all');
  window.dispatchEvent(new Event('arbiter:route-replaced'));
  tenantSelect.textContent='Semua tenant';
  tenantSelect.title=status?'Semua tenant':'Database belum terverifikasi; daftar tenant dikosongkan.';
  tenantDialog.close();renderTenantOptions();
  for(const link of document.querySelectorAll('.nav-link'))link.href=navigationMemory.destination(link.dataset.page,'all');
  document.querySelector('.wordmark').href='#/triage?tenant=all';
}
function renderTenantOptions(){
  const scope=routeScope(currentRoute?.params||new URLSearchParams());
  const known=new Set(tenantRows.map(row=>String(row.tenant)));
  for(const tenant of scope.tenants)if(!known.has(tenant))tenantRows.push({tenant});
  tenantOptions.innerHTML=tenantRows.map(row=>{const name=String(row.tenant);return `<label class="checkbox-label"><input type="checkbox" name="tenant" value="${esc(name)}" ${scope.tenants.includes(name)?'checked':''}>${esc(name)}</label>`;}).join('')||'<p class="meta">Belum ada tenant tersedia.</p>';
  const all=tenantForm.elements.all;all.checked=scope.all;
  for(const input of tenantOptions.querySelectorAll('input[name="tenant"]'))input.disabled=all.checked;
}
async function tenants(){
  if(databaseUnverified)return;
  const epoch=databaseEpoch;
  try{const data=await json('/api/tenants',{timeout:10000});if(epoch!==databaseEpoch)return;tenantRows=(data.tenants||[]);renderTenantOptions();}
  catch{if(epoch===databaseEpoch)tenantSelect.title='Daftar tenant belum dapat diperbarui. Scope saat ini tetap dipertahankan.';}
}
tenantSelect.addEventListener('click',()=>{renderTenantOptions();tenantDialog.showModal();});
tenantForm.addEventListener('change',event=>{
  if(event.target.name==='all')for(const input of tenantOptions.querySelectorAll('input[name="tenant"]'))input.disabled=event.target.checked;
  else if(event.target.name==='tenant'&&event.target.checked)tenantForm.elements.all.checked=false;
});
tenantForm.addEventListener('submit',event=>{
  event.preventDefault();const all=tenantForm.elements.all.checked;
  const selected=[...tenantOptions.querySelectorAll('input[name="tenant"]:checked')].map(input=>input.value);
  if(!all&&!selected.length){notify('Pilih setidaknya satu tenant atau Semua tenant.','error');return;}
  const p=new URLSearchParams(currentRoute.params);p.delete('tenant');for(const tenant of all?['all']:selected.sort())p.append('tenant',tenant);p.delete('offset');p.delete('alert');p.delete('alert_ids');
  const target=currentRoute.path.startsWith('/incidents/')?'/incidents':currentRoute.path;
  tenantDialog.close();router.navigate(withParams(target,p));
});
tenantDialog.querySelectorAll('[data-close-tenant-scope]').forEach(button=>button.addEventListener('click',()=>tenantDialog.close()));
document.querySelector('#refresh-workspace').addEventListener('click',async e=>{
  const button=e.currentTarget;button.disabled=true;await Promise.all([health(),tenants()]);main.dispatchEvent(new CustomEvent('arbiter:refresh'));button.disabled=false;
});
const sidebar=document.querySelector('#sidebar'),scrim=document.querySelector('#nav-scrim');
function openNav(){sidebar.classList.add('is-open');scrim.classList.add('is-open');document.querySelector('#open-navigation').setAttribute('aria-expanded','true');document.querySelector('#workspace').inert=true;sidebar.querySelector('.nav-link')?.focus();}
function closeNav(restore=true){const wasOpen=sidebar.classList.contains('is-open');sidebar.classList.remove('is-open');scrim.classList.remove('is-open');document.querySelector('#open-navigation').setAttribute('aria-expanded','false');document.querySelector('#workspace').inert=false;if(wasOpen&&restore)document.querySelector('#open-navigation').focus();}
document.querySelector('#open-navigation').addEventListener('click',openNav);
document.querySelector('#close-navigation').addEventListener('click',()=>closeNav());scrim.addEventListener('click',()=>closeNav());
const shell=document.querySelector('.app-shell'),sidebarToggle=document.querySelector('#toggle-sidebar');
const sidebarStorage=(()=>{try{return window.localStorage;}catch{return null;}})();
let sidebarState=readSidebarState(sidebarStorage);
function setSidebarState(next,persist=true){
  sidebarState=normalizeSidebarState(next);
  const collapsed=sidebarState==='collapsed';
  shell.classList.toggle('is-sidebar-collapsed',collapsed);
  const label=collapsed?'Tampilkan navigasi':'Sembunyikan navigasi';
  sidebarToggle.setAttribute('aria-expanded',String(!collapsed));
  sidebarToggle.setAttribute('aria-label',label);
  sidebarToggle.title=label;
  if(persist)writeSidebarState(sidebarStorage,sidebarState);
  if(collapsed)closeNav(false);
}
sidebarToggle.addEventListener('click',()=>setSidebarState(toggleSidebarState(sidebarState)));
setSidebarState(sidebarState,false);
const realtimeToggle=document.querySelector('#realtime-toggle');
let realtimeState={enabled:false,interval_seconds:30};
function paintRealtime(){
  const enabled=Boolean(realtimeState.enabled);
  realtimeToggle.setAttribute('aria-pressed',String(enabled));
  const label=enabled?`Monitor realtime: siap setiap ${realtimeState.interval_seconds} detik`:'Monitor realtime: nonaktif';
  realtimeToggle.setAttribute('aria-label',label);
  realtimeToggle.title=label;
}
function applyWorkspaceSettings(settings,applySidebarDefault=false){
  const realtime=settings?.realtime||{};
  realtimeState={enabled:Boolean(realtime.enabled),interval_seconds:Number(realtime.interval_seconds)||30};
  paintRealtime();
  if(applySidebarDefault&&['expanded','collapsed'].includes(settings?.ui?.sidebar_default))setSidebarState(settings.ui.sidebar_default);
}
async function loadWorkspaceSettings(){
  try{const body=await json('/api/settings',{timeout:10000});applyWorkspaceSettings(body.settings);}
  catch{/* Settings are optional; header keeps its safe defaults. */}
}
realtimeToggle.addEventListener('click',async e=>{
  const button=e.currentTarget,next=!realtimeState.enabled;
  button.disabled=true;
  try{
    const body=await json('/api/settings',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({realtime:{enabled:next,interval_seconds:realtimeState.interval_seconds}}) });
    applyWorkspaceSettings(body.settings);
    notify(next?`Monitor realtime disiapkan setiap ${realtimeState.interval_seconds} detik. Pengambilan Wazuh menyusul.`:'Monitor realtime dimatikan.',next?'success':'info');
    window.dispatchEvent(new CustomEvent('arbiter:realtime-changed',{detail:realtimeState}));
  }catch(error){notify(error.message,'error');}
  finally{button.disabled=false;}
});
window.addEventListener('arbiter:settings-saved',event=>{applyWorkspaceSettings(event.detail,true);});
window.addEventListener('arbiter:realtime-changed',event=>{if(event.detail){realtimeState={enabled:Boolean(event.detail.enabled),interval_seconds:Number(event.detail.interval_seconds)||30};paintRealtime();}});
sidebar.addEventListener('keydown',e=>{if(e.key==='Escape')closeNav();if(e.key==='Tab'&&sidebar.classList.contains('is-open')){const focusable=[...sidebar.querySelectorAll('a,button')].filter(el=>el.getClientRects().length);const first=focusable[0],last=focusable.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}});
const help=document.querySelector('#help-dialog');document.querySelector('#help-button').addEventListener('click',()=>help.showModal());help.querySelector('[data-close-dialog]').addEventListener('click',()=>help.close());
document.querySelector('.skip-link').addEventListener('click',e=>{e.preventDefault();main.focus();});
window.addEventListener('beforeunload',e=>{if(guard&&!guard()){e.preventDefault();e.returnValue='';}});
document.addEventListener('visibilitychange',()=>{if(!document.hidden)health();});
window.addEventListener('online',health);window.addEventListener('offline',health);
router.start();health();tenants();loadWorkspaceSettings();setInterval(health,15000);
