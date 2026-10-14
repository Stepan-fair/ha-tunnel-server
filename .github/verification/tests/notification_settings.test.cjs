const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Node {
 constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.textContent='';this.value='';this.checked=false;this.selected=false;this.disabled=false;}
 append(...nodes){this.children.push(...nodes);}
 replaceChildren(...nodes){this.children=nodes;}
 addEventListener(kind,fn){this.listeners[kind]=fn;}
}
const defaults={enabled:true,ha:true,mobile_targets:[],warning_days:3,funds_low:true,access_ending:true,access_stopped:true,access_recovered:true,connection:false};
async function run(role){
 const root=new Node('section'),document={createElement:t=>new Node(t),getElementById:()=>null};
 const ctx=vm.createContext({document,JSON,Number,Error,Array,Object,Set,RegExp,console});
 vm.runInContext(fs.readFileSync(process.argv[2]||'shared/notification_settings.js','utf8'),ctx);
 const calls=[];let lost=false,revision=0,services=['notify.mobile_app_phone','<img src=x>'],seq=0;
 const request=async(path,options)=>{calls.push({path,options});if(options){if(lost){lost=false;throw Error('network');}return {ok:true,status:200,json:async()=>({settings:defaults,revision:++revision})};}
 return {ok:true,status:200,json:async()=>({settings:{...defaults,mobile_targets:['notify.mobile_app_saved']},revision,csrf:'local-csrf',services,catalog_available:false,diagnostic:'mobile_catalog_unavailable'})};};
 const ui=ctx.mountNotificationSettings(root,request,()=> 'command-'+(++seq));await ui.load();
 assert.equal(calls.filter(c=>c.options).length,0,'page visit must not send messages');
 assert.equal(ui.targets.children.length,2,'keep selected unavailable target, exclude malicious labels');
 assert.ok(ui.targets.children.some(n=>n.value==='notify.mobile_app_saved'&&n.selected));
 assert.ok(ui.diagnostic.textContent.includes('телефон'));
 ui.fields.warning_days.value='0';await ui.save({preventDefault(){}});assert.equal(calls.filter(c=>c.options).length,0);
 ui.fields.warning_days.value='7';lost=true;await ui.save({preventDefault(){}});await ui.save({preventDefault(){}});
 const writes=calls.filter(c=>c.options);assert.equal(writes.length,2);assert.equal(writes[0].options.body,writes[1].options.body);
 assert.equal(writes[0].options.headers['X-CSRF-Token'],'local-csrf');
 assert.equal(JSON.parse(writes[0].options.body).settings.warning_days,7);
 assert.equal(calls.filter(c=>c.path.endsWith('/test')).length,0);
 lost=true;await ui.test();await ui.test();const tests=calls.filter(c=>c.path.endsWith('/test'));
 assert.equal(tests.length,2);assert.equal(tests[0].options.body,tests[1].options.body);
 assert.equal(JSON.parse(tests[0].options.body).settings,undefined);
 assert.equal(ui.fields.connection.checked,false);
 console.log('PASS '+role+' notification settings: independent form, safe recipients, bounded input, explicit test, durable command retry');
}
(async()=>{for(const role of process.argv[3]?[process.argv[3]]:['server','client'])await run(role);})().catch(e=>{console.error(e);process.exitCode=1;});
