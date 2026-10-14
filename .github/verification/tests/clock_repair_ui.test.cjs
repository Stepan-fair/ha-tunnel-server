const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Node {
 constructor(tag,text){this.tag=tag;this.textContent=text||'';this.children=[];this.listeners={};this.value='';}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 addEventListener(name,fn){this.listeners[name]=fn;}
}
const nodes=new Map();const ctx=vm.createContext({Date,Number,Error,JSON,encodeURIComponent,
 byId:id=>{if(!nodes.has(id))nodes.set(id,new Node('div'));return nodes.get(id);},
 element:(tag,text)=>new Node(tag,text),date:n=>String(n),commandId:()=> 'unique',notify:()=>{},
 button:(parent,text,fn)=>{const n=new Node('button',text);n.handler=fn;parent.append(n);return n;},api:()=>{throw Error('unexpected mutation');},confirm:()=>false});
vm.runInContext(fs.readFileSync('server/app/templates/clock_repair.js','utf8'),ctx);
assert.throws(()=>ctx.parseRepairInstant('2026-10-15T10:00'));
assert.equal(ctx.parseRepairInstant('2026-10-15T10:00:00+03:00'),1792047600);
ctx.renderClockRepair({old_anchor:2000,confirmed_now:1999.5,confirmed_snapshot:{id:'jitter',at:1999.5},reliable:true,repair_allowed:false,clients:[]});
assert.equal(nodes.get('clock-result').children.filter(n=>n.tag==='button').length,0);
ctx.renderClockRepair({old_anchor:2000,confirmed_now:null,confirmed_snapshot:null,reliable:false,clients:[]});
assert.equal(nodes.get('clock-result').children.filter(n=>n.tag==='button').length,0);
ctx.renderClockRepair({old_anchor:2000,confirmed_now:1000,confirmed_snapshot:{id:'a',at:1000},revision:'r',reliable:false,repair_allowed:true,clients:[{client_id:'c',domain:'<img>',hold:true,balance_kopecks:60000,paid_from:2000,paid_until:3000,timezone:'UTC',operation_ids:['purchase:one']}]});
const root=nodes.get('clock-result');assert.equal(root.children.filter(n=>n.tag==='button').length,1);
const form=root.children.find(n=>n.tag==='form');assert.ok(form);
assert.ok(form.children.some(n=>n.textContent.includes('<img>')));
assert.ok(form.children.some(n=>n.textContent.includes('purchase:one')));
console.log('PASS clock repair UI: explicit time offsets, proof gating, held period and original purchase preview');

(async()=>{
 const proposal={revision:'r',balance_kopecks:60000,old_period:{paid_from:2000,paid_until:3000,timezone:'UTC',anchor_day:31},new_period:{paid_from:1000,paid_until:4000,timezone:'UTC',anchor_day:31},reason:'Reason',operation_ids:['purchase:one']};
 const inputs=form.children.filter(n=>n.tag==='label').map(n=>n.children[0]);
 ['2026-10-15T10:00:00+03:00','2026-11-15T00:00:00+03:00','UTC','Reason'].forEach((v,i)=>inputs[i].value=v);
 const submit=form.children.find(n=>n.tag==='button'),calls=[];let lost=true;
 ctx.confirm=text=>{assert.ok(text.includes('31'));assert.ok(text.includes('purchase:one'));return true;};
 ctx.api=async(path,data)=>{
  calls.push({path,data});
  if(path.endsWith('/period-preview'))return {json:async()=>proposal};
  if(path.endsWith('/period-reconciliation')){if(lost){lost=false;throw Error('response lost');}return {};}
  return {json:async()=>({old_anchor:1000,confirmed_now:1000,confirmed_snapshot:{},clients:[]})};
 };
 await assert.rejects(submit.handler(),/response lost/);await submit.handler();
 assert.equal(calls.filter(c=>c.path.endsWith('/period-preview')).length,1);
 const sent=calls.filter(c=>c.path.endsWith('/period-reconciliation'));
 assert.equal(sent.length,2);assert.equal(sent[0].data.command_id,sent[1].data.command_id);
 assert.equal(sent[0].data.revision,'r');assert.equal(sent[0].data.operation_ids[0],'purchase:one');
 console.log('PASS clock repair UI: server calendar preview, anchor display and idempotent response-loss retry');
})().catch(error=>{console.error(error);process.exitCode=1;});
