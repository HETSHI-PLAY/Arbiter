import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';
import {createSelection} from '../../app/static/js/state/selection.js';
import {createNavigationMemory} from '../../app/static/js/state/navigation.js';
import {parseRoute, withParams} from '../../app/static/js/router.js';
import {tenantScope, tenantValues} from '../../app/static/js/state/scope.js';

// Execute the real shell without booting feature mounts, timers or networking.
const source=readFileSync(new URL('../../app/static/js/app.js',import.meta.url),'utf8').replace(/^import .*;\n/gm,'').replace('router.start();health();tenants();setInterval(health,15000);','');
function shell(){
  const nodes=new Map(), links=['triage','incidents'].map(page=>({dataset:{page},href:''}));
  const node=()=>({innerHTML:'',textContent:'',title:'',dataset:{},elements:{all:{}},classList:{contains:()=>false,remove(){}},addEventListener(){},querySelectorAll:()=>[],querySelector:()=>node(),close(){}});
  const location={hash:'#/database?tenant=Old&alert=21'}, replaced=[];
  const context=vm.createContext({URLSearchParams,Map,Set,AbortController,createSelection,createNavigationMemory,tenantScope,tenantValues,withParams,parseRoute,location,history:{replaceState(a,b,hash){location.hash=hash;replaced.push(hash);}},window:{addEventListener(){},dispatchEvent(){}},Event,document:{addEventListener(){},querySelector(selector){if(!nodes.has(selector))nodes.set(selector,node());return nodes.get(selector);},querySelectorAll:selector=>selector==='.nav-link'?links:[]},icon:()=>'',esc:String,createRouter:()=>({}),json:async()=>({tenants:[]}),clearTimeout(){},setTimeout(){}});
  vm.runInContext(source,context);
  return {context,nodes,links,replaced,run:code=>vm.runInContext(code,context)};
}

test('in-flight tenant response from old database cannot repopulate switched shell',async()=>{
  const h=shell();let resolve;
  h.context.json=()=>new Promise(done=>{resolve=done;});
  const pending=h.run('tenants()');
  h.run("currentRoute=parseRoute(location.hash);databaseChanged(null);databaseChanged({tenants:[{tenant:'New'}]})");
  resolve({tenants:[{tenant:'Old'}]});await pending;
  assert.equal(h.run('tenantRows.map(row=>row.tenant).join()'),'New');
});

test('database change clears shell selection, navigation, route details and old tenants before rehydration',()=>{
  const h=shell();
  h.run("currentRoute=parseRoute(location.hash);selection.toggle(21,true);navigationMemory.remember(parseRoute('#/triage?tenant=Old&search=secret&offset=90'));scrollPositions.set('old',99);tenantRows=[{tenant:'Old'}]");
  assert.equal(h.run('typeof databaseChanged'),'function');
  h.run('databaseChanged(null)');
  assert.equal(h.run('selection.size()'),0);
  assert.equal(h.run('selection.scope()'),'all');
  assert.equal(h.run('scrollPositions.size'),0);
  assert.equal(h.run('tenantRows.length'),0);
  assert.equal(h.run("navigationMemory.destination('triage','Old')"),'#/triage?tenant=Old');
  assert.equal(h.run('currentRoute.params.toString()'),'tenant=all');
  assert.equal(h.replaced.at(-1),'#/database?tenant=all');
  assert.ok(h.links.every(link=>!link.href.includes('Old')));
  h.run("databaseChanged({tenants:[{tenant:'New'}]})");
  assert.equal(h.run('tenantRows.map(row=>row.tenant).join()'),'New');
  assert.match(h.nodes.get('#tenant-scope-options').innerHTML,/New/);
  assert.doesNotMatch(h.nodes.get('#tenant-scope-options').innerHTML,/Old/);
  assert.match(source,/databaseChanged[,}]/,'shell passes the callback to feature context');
});
