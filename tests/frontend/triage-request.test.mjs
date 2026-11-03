import test from 'node:test';
import assert from 'node:assert/strict';
import {mount} from '../../app/static/js/features/triage/view.js';
import {createSelection} from '../../app/static/js/state/selection.js';

class Element extends EventTarget {
  constructor(){super();this.classList={add(){},remove(){},toggle(){}};this.value='';this.innerHTML='';}
  setAttribute(){} removeAttribute(){} close(){}
}
async function requestsFor(search){
  const controls=new Map(), root=new Element(), requests=[];
  root.querySelector=s=>{if(!controls.has(s))controls.set(s,new Element());return controls.get(s);};
  root.querySelectorAll=()=>[];
  const controller=new AbortController(), original=globalThis.fetch;
  globalThis.fetch=async url=>{
    requests.push(new URL(url,'http://synthetic.invalid'));
    return new Response(JSON.stringify(String(url).includes('/summary')?{alerts:0,events:0,unique_source_ips:0,unique_agents:0,incident_cases:0}:{items:[],total:0}));
  };
  let dispose;
  try {
    dispose=mount({root,route:{params:new URLSearchParams(search)},signal:controller.signal,selection:createSelection('all'),navigate(){},notify(){}});
    await new Promise(resolve=>setTimeout(resolve,10));
    return requests;
  } finally {controller.abort();dispose?.();globalThis.fetch=original;}
}

test('default Triage sends the same explicit unreviewed scope to list and summary',async()=>{
  const requests=await requestsFor('');
  for(const path of ['/api/alerts','/api/triage/summary']){
    const params=requests.find(url=>url.pathname===path).searchParams;
    assert.equal(params.get('review_status'),'unreviewed',path);
  }
  const list=requests.find(url=>url.pathname==='/api/alerts').searchParams;
  assert.equal(list.get('limit'),'50');
  assert.equal(list.get('offset'),'0');
});

test('explicit review scope and repeated tenants survive queue and summary requests',async()=>{
  for(const review of ['all','reviewed','unreviewed']){
    const requests=await requestsFor(`tenant=Alpha&tenant=Beta&review_status=${review}&facet=rule_id&facet_value=5703&secondary_facet=agent&secondary_facet_value=node&limit=25&offset=25`);
    for(const url of requests){
      assert.deepEqual(url.searchParams.getAll('tenant'),['Alpha','Beta']);
      assert.equal(url.searchParams.get('facet'),'rule_id');
      assert.equal(url.searchParams.get('facet_value'),'5703');
      assert.equal(url.searchParams.get('secondary_facet'),'agent');
      assert.equal(url.searchParams.get('secondary_facet_value'),'node');
      assert.equal(url.searchParams.get('review_status'),review);
    }
  }
});
