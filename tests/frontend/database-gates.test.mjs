import test from 'node:test';
import assert from 'node:assert/strict';
import {mount} from '../../app/static/js/features/database/view.js';

const profiles = [{id:'local',mode:'read_write',masked_url:'postgresql://user:***@local.invalid/db'}, {id:'remote',mode:'read_write',masked_url:'postgresql://user:***@remote.invalid/db'}];
const status = (id='local') => ({active_profile:profiles.find(p=>p.id===id),profiles,tenants:[{tenant:id+'-tenant',count:2}],stats:{}});
async function harness(handler = () => status(), extra = {}) {
  const listeners={}, elements=new Map(), notices=[], calls=[], confirmations=[];
  let html='';
  const root={
    get innerHTML(){return html;},
    set innerHTML(value){html=value;elements.clear();for(const match of value.matchAll(/<(input|select|button|div)\b([^>]*\bid="([^"]+)"[^>]*)>/g)){
      const [,tag,attrs,id]=match, body=value.slice(match.index+match[0].length).split('</'+tag+'>')[0];
      let val=attrs.match(/\bvalue="([^"]*)"/)?.[1]||'';
      if(tag==='select')val=body.match(/<option value="([^"]*)" selected/)?.[1]??body.match(/<option value="([^"]*)"/)?.[1]??'';
      elements.set('#'+id,{id,value:val,checked:false,style:{},textContent:'',innerHTML:'',addEventListener(){}});
    }},
    querySelector(selector){return elements.get(selector)||null;},
    addEventListener(type,fn){listeners[type]=fn;},
  };
  globalThis.fetch=async(url,options={})=>{const body=options.body?JSON.parse(options.body):null;calls.push({url,body});const data=await handler(url,body);return {ok:true,json:async()=>data};};
  globalThis.confirm=message=>{confirmations.push(message);return true;};
  await mount({root,route:{params:new URLSearchParams('tenant=Alpha')},signal:new AbortController().signal,notify:(...args)=>notices.push(args),...extra});
  return {root,calls,notices,confirmations,elements,async click(action,profile='remote'){const btn={dataset:{action,profile},disabled:false,textContent:''};await listeners.click({target:{closest:()=>btn}});},input(id,value){const target=elements.get(id);target.value=value;listeners.input?.({target});},change(id,value){const target=elements.get(id);target.value=value;listeners.input?.({target});listeners.change?.({target});}};
}

test('switch invalidates workspace before mutation and verifies exact target before success',async()=>{
  const events=[];let switched=false;
  const h=await harness((url)=>{if(url.endsWith('/switch')){events.push('write');switched=true;return {}; }if(switched)events.push('readback');return status(switched?'remote':'local');}, {databaseChanged:data=>events.push(data?'rehydrate':'invalidate')});
  await h.click('switch-profile');
  assert.deepEqual(events,['invalidate','write','readback','rehydrate']);
  assert.equal(h.notices.filter(([,kind])=>kind==='success').length,1);
});

test('purge requires a fresh preview of unchanged filters and database',async()=>{
  let active='local';
  const h=await harness((url,body)=>url.includes('/purge-')?{dry_run:body.dry_run,count:4,deleted:4}:status(active));
  await h.click('execute-purge-alerts');
  assert.equal(h.calls.filter(c=>c.body?.dry_run===false).length,0,'no preview');
  await h.click('dry-run-alerts');
  h.change('#purge-alerts-tenant','Other');
  await h.click('execute-purge-alerts');
  assert.equal(h.calls.filter(c=>c.body?.dry_run===false).length,0,'edited filters');
  await h.click('dry-run-alerts');
  active='remote';
  await h.click('execute-purge-alerts');
  assert.equal(h.calls.filter(c=>c.body?.dry_run===false).length,0,'changed database');
});

test('incidents disclose global scope before preview and in confirmation',async()=>{
  const h=await harness((url,body)=>url.includes('/purge-')?{dry_run:body.dry_run,count:4,deleted:4}:status());
  assert.match(h.root.innerHTML,/GLOBAL[^<]*semua tenant/);
  await h.click('execute-purge-incidents');
  assert.equal(h.calls.some(c=>c.body?.dry_run===false),false);
  await h.click('dry-run-incidents');
  assert.match(h.elements.get('#purge-incidents-result').textContent,/GLOBAL.*semua tenant/);
  await h.click('execute-purge-incidents');
  assert.match(h.confirmations.at(-1),/GLOBAL: semua tenant; scope workspace diabaikan/);
  assert.equal(h.calls.filter(c=>c.body?.dry_run===false).length,1);
});

test('preview expires, is single-use, and freezes exact alert cutoff',async()=>{
  const originalNow=Date.now;let now=2000000000000;Date.now=()=>now;
  try {
    const h=await harness((url,body)=>url.includes('/purge-')?{dry_run:body.dry_run,count:4,deleted:4}:status());
    await h.click('dry-run-alerts');now+=60001;
    await h.click('execute-purge-alerts');
    assert.equal(h.calls.some(c=>c.body?.dry_run===false),false);
    await h.click('dry-run-alerts');now+=2000;
    await h.click('execute-purge-alerts');
    const writes=h.calls.filter(c=>c.body?.dry_run===false);
    assert.equal(writes.length,1);
    const preview=h.calls.filter(c=>c.body?.dry_run===true).at(-1).body;
    assert.deepEqual(writes[0].body,{...preview,dry_run:false});
    assert.equal(preview.older_than_days,null);
    assert.ok(preview.time_to);
    await h.click('execute-purge-alerts');
    assert.equal(h.calls.filter(c=>c.body?.dry_run===false).length,1);
  } finally {Date.now=originalNow;}
});

test('duplicate execution while status readback is pending cannot consume preview twice',async()=>{
  let hold=false, resolve;
  const h=await harness((url,body)=>{
    if(url.includes('/purge-'))return {dry_run:body.dry_run,count:4,deleted:4};
    if(hold){hold=false;return new Promise(done=>{resolve=done;});}
    return status();
  });
  await h.click('dry-run-alerts');hold=true;
  const first=h.click('execute-purge-alerts');
  await h.click('execute-purge-alerts');
  resolve(status());await first;
  assert.equal(h.calls.filter(c=>c.body?.dry_run===false).length,1);
});

test('preview expiring during preflight readback cannot execute',async()=>{
  const originalNow=Date.now;let now=2000000000000, expire=false;Date.now=()=>now;
  try {
    const h=await harness((url,body)=>{if(url.includes('/purge-'))return {dry_run:body.dry_run,count:4,deleted:4};if(expire)now+=60001;return status();});
    await h.click('dry-run-alerts');expire=true;
    await h.click('execute-purge-alerts');
    assert.equal(h.calls.some(c=>c.body?.dry_run===false),false);
  } finally {Date.now=originalNow;}
});

test('read-only, failed preview, malformed preview, and refresh all block execution',async()=>{
  for(const failure of ['read-only','offline','malformed','refresh']){
    const h=await harness((url,body)=>{
      if(url.includes('/purge-')){if(failure==='offline')throw Error('synthetic offline');return failure==='malformed'?{}:{dry_run:body.dry_run,count:4,deleted:4};}
      return failure==='read-only'?{...status(),active_profile:{...profiles[0],mode:'read_only'}}:status();
    });
    await h.click('dry-run-alerts');
    if(failure==='refresh')await h.click('refresh-status');
    await h.click('execute-purge-alerts');
    assert.equal(h.calls.some(c=>c.body?.dry_run===false),false,failure);
  }
});

test('filter input during preview invalidates the in-flight result before blur',async()=>{
  let resolve;
  const h=await harness((url,body)=>url.includes('/purge-')?new Promise(done=>{resolve=done;}):status());
  const pending=h.click('dry-run-alerts');
  while(!resolve)await new Promise(done=>setImmediate(done));
  h.input('#purge-from','2026-01-01T00:00');
  resolve({dry_run:true,count:4});await pending;
  assert.match(h.notices.at(-1)?.[0] || '',/berubah|baru/);
});

test('maintenance readback on a different database does not announce verified success',async()=>{
  let executed=false;
  const h=await harness((url,body)=>{if(url.includes('/purge-')){if(!body.dry_run)executed=true;return {dry_run:body.dry_run,count:4,deleted:4};}return status(executed?'remote':'local');});
  await h.click('dry-run-alerts');await h.click('execute-purge-alerts');
  assert.equal(h.notices.some(([,kind])=>kind==='success'),false);
  assert.equal(h.notices.some(([,kind])=>kind==='error'),true);
});

test('switch readback failure clears stale database display until explicit refresh',async()=>{
  let switched=false;
  const h=await harness(url=>{if(url.endsWith('/switch')){switched=true;return {};}if(switched)throw Error('synthetic offline');return status();},{databaseChanged:()=>{}});
  await h.click('switch-profile');
  assert.doesNotMatch(h.root.innerHTML,/local-tenant/);
  assert.match(h.root.innerHTML,/refresh-status/);
});

test('switch mismatch or failed readback never announces success',async()=>{
  for(const failure of ['wrong-profile','wrong-target','offline']){
    let switched=false;
    const h=await harness(url=>{if(url.endsWith('/switch')){switched=true;return {};}if(switched&&failure==='offline')throw Error('synthetic offline');if(switched&&failure==='wrong-target')return {...status('remote'),active_profile:{...profiles[1],masked_url:'postgresql://user:***@other.invalid/db'}};return status();},{databaseChanged:()=>{}});
    await h.click('switch-profile');
    assert.equal(h.notices.some(([,kind])=>kind==='success'),false,failure);
    assert.equal(h.notices.some(([,kind])=>kind==='error'),true,failure);
  }
});
