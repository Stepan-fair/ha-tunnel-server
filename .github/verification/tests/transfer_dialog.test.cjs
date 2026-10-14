const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.resolve(__dirname, '../server/app/templates/app.js'), 'utf8');
const start = source.indexOf('let transferTarget=');
const end = source.indexOf('function showTab(tab)', start);
assert.ok(start >= 0 && end > start);
class Node {
  constructor() { this.value = ''; this.disabled = false; this.listeners = {}; this.open = false; }
  addEventListener(name, action) { this.listeners[name] = action; }
  showModal() { this.open = true; }
  close() { this.open = false; }
}
const ids = ['transfer-domain', 'transfer-description', 'transfer-error', 'transfer-confirm', 'transfer-close', 'transfer-dialog', 'transfer-form'];
const nodes = Object.fromEntries(ids.map(id => [id, new Node()]));
const requests = [], shown = [];
let complete;
const pending = new Promise(resolve => { complete = resolve; });
const context = vm.createContext({
  byId: id => nodes[id], encodeURIComponent, commandId:()=>"stable-command", confirm:()=>true,
  api: async (url, data) => { requests.push({url, data}); await pending; return {json: async () => ({invitation: 'synthetic-code'})}; },
  showCode: result => shown.push(result)
});
vm.runInContext(source.slice(start, end), context);
(async () => {
  vm.runInContext("openTransfer({id:'alpha-id',domain:'alpha.example.org',revision:7})", context);
  assert.equal(nodes['transfer-confirm'].disabled, true);
  nodes['transfer-domain'].value = 'wrong.example.org'; nodes['transfer-domain'].listeners.input();
  assert.equal(nodes['transfer-confirm'].disabled, true);
  nodes['transfer-domain'].value = 'alpha.example.org'; nodes['transfer-domain'].listeners.input();
  assert.equal(nodes['transfer-confirm'].disabled, false);
  const event = {preventDefault() {}};
  const first = nodes['transfer-form'].listeners.submit(event);
  nodes['transfer-domain'].listeners.input();
  assert.equal(nodes['transfer-confirm'].disabled, true, 'Typing must not enable a second pending transfer');
  await nodes['transfer-form'].listeners.submit(event);
  assert.equal(requests.length, 1, 'Only one request may issue the transfer code');
  nodes['transfer-close'].listeners.click();
  assert.equal(nodes['transfer-dialog'].open, true, 'Pending operation must retain its target');
  complete(); await first;
  assert.equal(shown.length, 1);
  assert.equal(shown[0].invitation, 'synthetic-code');
  assert.equal(nodes['transfer-dialog'].open, false);
  assert.deepEqual(JSON.parse(JSON.stringify(requests[0])), {url:'api/clients/alpha-id/invitation/transfer',data:{revision:7,confirm_domain:'alpha.example.org',command_id:'stable-command',replace_pending:false}});
  vm.runInContext("openTransfer({id:'alpha-id',domain:'alpha.example.org',revision:8,pending_transfer:true})",context);
  assert.match(nodes['transfer-description'].textContent,/замен/);
  console.log('PASS: exact domain confirmation and one pending transfer request');
})().catch(error => { console.error(error); process.exitCode = 1; });
