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

// The whole render(), not just the live table: any exception in it reads to
// the user as "service injoignable", since the poll's catch cannot tell a
// broken page from an unreachable service. A local variable once shadowed
// the rows() helper and every poll failed that way.
{
  const src = scripts.find(s => s.includes('function render(d)'));
  function el() {
    return new Proxy({style: {}, classList: {toggle() {}, add() {}, remove() {}},
      appendChild() {}, append() {}, prepend() {}, remove() {}, replaceChildren() {},
      insertBefore() {}, removeChild() {}, addEventListener() {}, setAttribute() {},
      closest() { return null; }, querySelector() { return el(); },
      querySelectorAll() { return []; }, cloneNode() { return el(); },
      getBoundingClientRect() { return {width: 300, height: 100, left: 0, top: 0}; },
      getContext() { return new Proxy({}, {get: () => () => ({})}); }},
      {get(t, k) { return k in t ? t[k] : (t[k] = ''); }, set(t, k, v) { t[k] = v; return true; }});
  }
  const ids = {};
  const media = () => ({matches: false, addEventListener() {}});
  const ctx = {console, URL, AbortSignal, Intl, Date, Math, JSON,
    document: {createElement: el, getElementById: id => ids[id] || (ids[id] = el()),
               querySelector: () => el(), querySelectorAll: () => [],
               documentElement: el(), body: el(), addEventListener() {}},
    location: {href: 'https://x/devinx/dashboard', search: ''}, history: {replaceState() {}},
    localStorage: {getItem() { return null; }, setItem() {}}, matchMedia: media,
    window: {matchMedia: media, addEventListener() {}, devicePixelRatio: 1},
    setInterval() {}, setTimeout() {}, fetch: () => new Promise(() => {}),
    getComputedStyle: () => ({getPropertyValue: () => ''}), requestAnimationFrame() {},
    ResizeObserver: class { observe() {} }};
  vm.createContext(ctx);
  vm.runInContext(src, ctx);
  ctx.render({});
  ctx.render({service: {accounts: [{name: 'a', pro: true, share: 0.5, blocked_for: 0},
                                   {name: 'idle', pro: true, share: 0, blocked_for: 3600}]},
              swe: {by_account: {a: {turns: 3, refusals: 1}}}});
  console.log('Dashboard full render on empty and blocked-account payloads: OK');
}
