"""Exercise shipped Shodan controls with a small DOM adapter, without a server."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from app.config import ROOT


class ShodanRuntimeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node is needed for the JavaScript runtime check')
    def test_domain_selection_toggle_status_and_example_use_real_ui_handlers(self):
        harness = r'''
const assert=require('node:assert/strict');
class Element {
  constructor(tag,text=''){this.tag=tag;this.children=[];this._text=text||'';this.value='';this.dataset={};this.events={};}
  append(...nodes){this.children.push(...nodes);if(this.tag==='select'&&!this.value&&nodes[0])this.value=nodes[0].value;}
  replaceChildren(){this.children=[];this.value='';this._text='';}
  addEventListener(name,callback){this.events[name]=callback;}
  set textContent(t){this._text=t;}
  get textContent(){return this._text+this.children.map(n=>n.textContent||'').join(' ');}
}
const elements={};global.$=id=>elements[id]||(elements[id]=new Element(id));
global.el=(tag,text)=>new Element(tag,text);global.date=s=>s||'unknown';
global.document={querySelector:()=>$('nav')};global.currentView='shodan';
global.notice=()=>{};global.load=async()=>{};
const posts=[];
let fixture={offline:false,companies:[{id:'client',name:'Client',domains:['client.example']}],observations:[],
 monitor:{search_limit_24h:10,search_requests_24h:1,targets:[{id:'t',company_id:'client',company_name:'Client',
 domain:'client.example',enabled:true,catalog_valid:true,last_run:{status:'ok',total:200,returned:100,observations:98,partial:true}}]},
 runtime:{running:true,shodan_monitor:{status:'ok'}}};
global.fetch=async path=>({ok:true,json:async()=>path.endsWith('/example')?{example_only:true,observations:[]}:fixture});
global.post=async(path,body)=>{posts.push({path,body});fixture.monitor.targets[0].enabled=body.enabled;return {status:'ok'};};
function all(node,tag){return node.children.flatMap(n=>[...(n.tag===tag?[n]:[]),...all(n,tag)]);}
'''
        checks = r'''
(async()=>{
  await $('nav').events.click();
  const box=$('shodan-monitor');assert.equal(box.hidden,false);
  assert.match(box.textContent,/200/);assert.match(box.textContent,/поиск неполный/);
  const form=all(box,'form')[0],selects=all(form,'select');
  assert.equal(selects[0].value,'client');assert.equal(selects[1].value,'client.example');
  const toggle=all(box,'button')[0];await toggle.onclick();
  assert.deepEqual(posts[0],{path:'/api/shodan/monitor',body:{company_id:'client',domain:'client.example',enabled:false}});
  const newForm=all(box,'form')[0];await newForm.onsubmit({preventDefault(){}});
  assert.equal(posts[1].body.enabled,true);
  await $('shodan-example').onclick();assert.equal(box.hidden,true);assert.equal(posts.length,2);
  console.log('Shodan UI runtime passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
'''
        with tempfile.TemporaryDirectory() as tmp:
            script=Path(tmp)/'shodan-runtime.cjs'
            script.write_text(harness+'\n'+(ROOT/'app/assets/shodan.js').read_text()+'\n'+checks)
            done=subprocess.run(['node',str(script)],text=True,capture_output=True,timeout=15)
            self.assertEqual(done.returncode,0,done.stderr)
