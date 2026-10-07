const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const app = fs.readFileSync(process.argv[2] || path.resolve(__dirname, '../server/app/templates/app.js'), 'utf8');
const start = app.indexOf('function updateBillingOverview(');
assert.ok(start >= 0, 'Server must expose financial values on the connection card');
const end = app.indexOf('\nfunction makeCard(', start);
assert.ok(end > start);
class Node {
  constructor(tag) { this.tagName = tag; this.children = []; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
}
const context = vm.createContext({element(tag, text, cls) {
  const node = new Node(tag); node.textContent = text === undefined ? '' : String(text);
  node.className = cls || ''; return node;
}});
vm.runInContext(app.slice(start, end), context);
const root = new Node('div');
context.root = root;
context.billing = {balance:'600,00 ₽', price:'300,00 ₽ / месяц', paid:'до 14.11.2026 включительно', funds:'до 14.01.2027 включительно'};
vm.runInContext('updateBillingOverview(root, billing)', context);
assert.equal(root.children.length, 4);
assert.deepEqual(root.children.map(n => n.children[1].textContent), Object.values(context.billing));
const retained = root.children.slice();
context.billing = {balance:'0,00 ₽', price:'0,00 ₽ / месяц', paid:'Бессрочно', funds:'Бессрочно'};
vm.runInContext('updateBillingOverview(root, billing)', context);
root.children.forEach((node, index) => assert.strictEqual(node, retained[index], 'Polling must retain existing overview nodes'));
assert.equal(root.children[2].children[1].textContent, 'Бессрочно');
context.billing = null;
vm.runInContext('updateBillingOverview(root, billing)', context);
assert.ok(root.children.every(n => n.children[1].textContent === 'Нет данных'), 'Missing finance must clear stale values');
context.billing = {balance:'<img src=x onerror=alert(1)>'};
vm.runInContext('updateBillingOverview(root, billing)', context);
assert.equal(root.children[0].children[1].textContent, context.billing.balance);
assert.ok(root.children.every(n => n.children.every(c => !c.children.length)), 'Values are text, never HTML');
console.log('PASS: financial summary rendering, free tariff, stable polling, missing data and text-only rendering');
