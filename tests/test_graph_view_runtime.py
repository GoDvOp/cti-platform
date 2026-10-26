import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from app.config import ROOT
from app.graph_view import export
from app.storage import CTIStore
from app.collectors import ingest
from app.models import Publication


class GraphViewRuntimeTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('node'), 'Node is optional; needed only for the JavaScript runtime check')
    def test_exported_script_initializes_filters_renders_and_schedules_refresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = CTIStore(root / 'db.sqlite3')
            store.load_companies([{'id': 'alpha', 'name': 'Example Co', 'sector': 'Example', 'aliases': []}])
            pub = Publication('test', 'https://example.org/program', '__SCRIPT__ is untrusted text',
                'Fictional program.', published_at='2026-10-24T12:00:00Z', collected_at='2026-10-24T12:01:00Z',
                metadata={'bug_bounty_program': {'name': '__SCRIPT__', 'company_name': 'Example Co',
                    'platform': 'Fictional Bounty', 'url': 'https://example.org/program'}})
            ingest(store, [pub])
            export(store, root / 'report', as_of='2026-10-24T12:02:00Z')
            page = (root / 'report/graph_view.html').read_text()
            self.assertIn('"name":"__SCRIPT__"', page)
            self.assertNotIn('<script>__SCRIPT__', page)
            data = (root / 'report/graph_view.json').read_text()
            # Execute the actual shipped script against a small DOM/canvas adapter.
            # This catches runtime initialization and filter failures without a browser dependency.
            harness = r'''
const assert=require('assert');
let drawn=0, delay=null;
const callbacks={}, timers=[];
function el(id){return {textContent:'',value:'',checked:false,hidden:false,style:{},children:[],
  append(...x){this.children.push(...x)},replaceChildren(){this.children=[]},
  addEventListener(type,cb){callbacks[id+':'+type]=cb},
  getBoundingClientRect(){return {width:1200,height:700,left:0,top:0}},
  setPointerCapture(){},getContext(){return new Proxy({}, {get(o,k){return (...args)=>{drawn++}},set(){return true}})}
};}
const elements={};
global.document={getElementById(id){return elements[id]||(elements[id]=el(id))},
 createElement(id){return el(id)},createTextNode(text){return {textContent:text}}};
document.getElementById('graph-data').textContent=__PAYLOAD__;
global.window={devicePixelRatio:1,addEventListener(){}};
global.sessionStorage={getItem(){return null},setItem(){}};
global.requestAnimationFrame=cb=>{timers.push(cb)};
global.setInterval=(cb,ms)=>{delay=ms};
global.location={reload(){}};
'''.replace('__PAYLOAD__', json.dumps(data))
            checks = r'''
assert(drawn>0);assert.strictEqual(delay,60000);
assert(shownNodes.length>0 && shownEdges.length>0);
mode.value='bounty';callbacks['mode:change']();
assert(shownEdges.some(e=>e.type==='HAS_PUBLIC_BUG_BOUNTY'));
mode.value='notice';callbacks['mode:change']();assert.strictEqual(shownEdges.length,0);
mode.value='threat';callbacks['mode:change']();assert(shownEdges.every(e=>!e.properties.view_layer));
details('Unsafe link',{url:'javascript:alert(1)'});assert.strictEqual(document.getElementById('detail-links').children.length,0);
details('Evidence',{url:'https://example.org'});assert.strictEqual(document.getElementById('detail-links').children.length,2);
'''
            script = root / 'runtime.cjs'
            script.write_text(harness + '\n' + (ROOT / 'app/assets/graph_view.js').read_text() + '\n' + checks)
            done = subprocess.run(['node', str(script)], text=True, capture_output=True, timeout=15)
            self.assertEqual(done.returncode, 0, done.stderr)
