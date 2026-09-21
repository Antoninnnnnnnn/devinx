// Validate the shipped script and the new table renderer without a browser/CDN.
// No HTML string from the service may be used as markup in the live table.
'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const html = fs.readFileSync('tools/dashboard.html', 'utf8');
const scripts = Array.from(html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g), m => m[1]);
for (const script of scripts) new vm.Script(script);
const source = scripts.find(s => s.includes('function renderActiveRequests'));
assert.ok(source, 'live renderer is missing');
const start = source.indexOf('function renderActiveRequests');
const end = source.indexOf('\nfunction render(d)', start);
assert.ok(end > start);
function element() {
  return {
    children: [], textContent: '',
    appendChild(child) { this.children.push(child); },
    replaceChildren() { this.children = []; },
    set innerHTML(_) { throw new Error('Unsafe HTML assignment'); }
  };
}
const target = element();
const context = {document: {createElement: element}, $: () => target, dur: value => `${value}s`};
vm.createContext(context);
vm.runInContext(source.slice(start, end), context);
context.renderActiveRequests(undefined);
assert.match(target.children[0].children[0].textContent, /Non disponible/);
context.renderActiveRequests([]);
assert.match(target.children[0].children[0].textContent, /Aucune/);
const hostile = '<img src=x onerror=alert(1)>';
context.renderActiveRequests([{id: hostile, model: 'swe-2-max', phase: 'streaming',
                               elapsed: 5, phase_elapsed: 2}]);
assert.equal(target.children.length, 1);
assert.equal(target.children[0].children.length, 5);
assert.equal(target.children[0].children[0].textContent, hostile);
assert.equal(target.children[0].children[2].textContent, 'Réception');
console.log('Dashboard syntax, empty/legacy states and safe live-table rendering: OK');
