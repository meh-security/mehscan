import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';
import { collect } from './backend.mjs';
const compiler = createRequire(import.meta.url).resolve('typescript');
const nodeTypes = path.dirname(createRequire(import.meta.url).resolve('@types/node/package.json'));

test('browser scope defers only resolved ordinary DOM GET/HEAD, preserving credential and mutation requests', () => {
  const f = fixture();
  try {
    const source = `export {}; declare const url: string; declare const init: RequestInit;
      fetch(url); fetch(url, {}); fetch(url, {method: 'HEAD'});
      fetch(url, {method: 'POST'}); fetch(url, {headers: {Authorization: 'Bearer token'}});
      fetch(url, {credentials: 'include'}); fetch(url, init); fetch(url, {...init});
      function custom(fetch: (url: string) => unknown) { fetch(url); }
    `;
    fs.writeFileSync(path.join(f.root, 'app.ts'), source);
    const ts = createRequire(import.meta.url)('typescript');
    const parsed = ts.createSourceFile('app.ts', source, ts.ScriptTarget.Latest, true);
    const queries = [];
    function visit(node) {
      if (ts.isCallExpression(node) && node.expression.getText(parsed) === 'fetch') {
        const argument = node.arguments[0];
        queries.push({evidence_id: String(queries.length), role: 'endpoint', sink: {}, operand: {
          path: 'app.ts', start: {byte_offset: argument.getStart(parsed)}, end: {byte_offset: argument.end}}});
      }
      ts.forEachChild(node, visit);
    }
    visit(parsed);
    const context = JSON.parse(fs.readFileSync(f.context));
    context.projects[0].runtime = 'browser';
    fs.writeFileSync(f.context, JSON.stringify(context));
    const request = {...f.request, queries};
    const deferred = snapshot => snapshot.observations.filter(o => o.facts.some(v => v.kind === 'browser_request_context' && v.remaining_checks.includes('ordinary_get_head'))).map(o=>o.evidence_id);
    const browser = collect(request);
    assert.deepEqual(deferred(browser), ['0', '1', '2']);
    assert.equal(browser.observations.filter(o=>o.facts.some(v=>v.kind==='browser_request_context')).length,8);
    context.projects[0].runtime = 'server';
    fs.writeFileSync(f.context, JSON.stringify(context));
    assert.deepEqual(deferred(collect(request)), []);
    context.projects[0].runtime = 'browser';
    fs.writeFileSync(f.context, JSON.stringify(context));
    fs.writeFileSync(path.join(f.root, 'app.ts'), source + '\nfetch = (() => Promise.resolve(new Response())) as typeof fetch;');
    assert.deepEqual(deferred(collect(request)), []);
  } finally { f.cleanup(); }
});

function fixture(extension = 'ts') {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'mehscan-ts-'));
  const typed = ['ts', 'tsx'].includes(extension);
  const expression = extension === 'tsx' ? '<div dangerouslySetInnerHTML={{__html: selected(input)}} />' : 'readFileSync(selected(input))';
  const source = `import { makePath as selected } from './helpers';\nconst prefix = '🙂';\nexport function run(input${typed ? ': string' : ''}) { return ${expression}; }\n`;
  fs.writeFileSync(path.join(root, `app.${extension}`), source);
  fs.writeFileSync(path.join(root, 'helpers.ts'), 'export function makePath(value: string) { return "storage/" + value; }\n');
  const context = path.join(root, 'context.json');
  fs.writeFileSync(context, JSON.stringify({ typescript_path: compiler, projects: [{ id: 'app', sources: [`app.${extension}`, 'helpers.ts'],
    compiler_options: { allowJs: true, jsx: 'preserve', target: 'ES2022', module: 'commonjs', strict: true } }] }));
  const text = 'selected(input)';
  const start = Buffer.byteLength(source.slice(0, source.indexOf(text)));
  const query = { evidence_id: 'one', role: 'path', sink: {}, operand: { path: `app.${extension}`, start: { byte_offset: start }, end: { byte_offset: start + Buffer.byteLength(text) } } };
  return { root, context, query, request: { schema_version: '1', root, context_path: context, queries: [query] }, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

test('incoming parameter arguments resolve imported aliases in TS/JS without implying complete or safe callers', () => {
  for (const extension of ['ts', 'js']) {
    const f = fixture(extension);
    try {
      const annotation = extension === 'ts' ? ': string' : '';
      const source = `export function target(value${annotation}) { return fetch(value); }
        export function unrelated(value${annotation}) { return value; }`;
      fs.writeFileSync(path.join(f.root, `app.${extension}`), source);
      fs.writeFileSync(path.join(f.root, `driver.${extension}`),
        `import {target as selected, unrelated} from './app';
        const input = '🙂/local'; selected(input); unrelated('not-a-caller');`);
      const context = JSON.parse(fs.readFileSync(f.context));
      context.projects[0].sources = [`driver.${extension}`];
      fs.writeFileSync(f.context, JSON.stringify(context));
      const start = source.indexOf('value', source.indexOf('fetch('));
      f.query.role = 'endpoint';
      f.query.operand.start.byte_offset = start;
      f.query.operand.end.byte_offset = start + 5;
      const snapshot = collect(f.request);
      const facts = snapshot.observations[0].facts;
      const args = facts.filter(v => v.kind === 'local_call_argument');
      assert.deepEqual(args.map(v => [v.location.path, v.value]), [[`driver.${extension}`, 'input']]);
      assert.ok(args[0].remaining_checks.includes('parameter_writes_and_runtime_dispatch_not_proven'));
      const boundary = facts.find(v => v.value === 'observed_parameter_callers:1;indexed_calls:1');
      assert.ok(boundary.remaining_checks.includes('unobserved_callers_and_parameter_writes'));
      assert.ok(snapshot.sources.some(v => v.path === `driver.${extension}`));
      const bytes = fs.readFileSync(path.join(f.root, `driver.${extension}`));
      assert.equal(bytes.subarray(args[0].location.start.byte_offset, args[0].location.end.byte_offset).toString(), 'input');
      assert.ok(!facts.some(v => v.kind === 'fixed_filesystem_path'));
    } finally { f.cleanup(); }
  }
});

test('incoming navigation caps callers, flags unsupported argument mapping and does not conflate method names', () => {
  const f = fixture();
  try {
    const source = `class A { read(value: string) { return fetch(value); } }
      class B { read(value: string) { return value; } }
      const a = new A(); const b = new B(); b.read('other');
      ${Array.from({length: 10}, (_, i) => `a.read('caller-${i}');`).join('\n')}`;
    fs.writeFileSync(path.join(f.root, 'app.ts'), source);
    const start = source.indexOf('value', source.indexOf('fetch('));
    f.query.operand.start.byte_offset = start;
    f.query.operand.end.byte_offset = start + 5;
    const facts = collect(f.request).observations[0].facts;
    const args = facts.filter(v => v.kind === 'local_call_argument');
    assert.equal(args.length, 8);
    assert.ok(args.every(v => v.value.startsWith("'caller-")));
    assert.ok(facts.some(v => v.remaining_checks.includes('caller_locations_truncated')));
    for (const declaration of ['value: string = "default"', '...value: string[]']) {
      const text = `export function target(${declaration}) { return fetch(value); }
        target('candidate');`;
      fs.writeFileSync(path.join(f.root, 'app.ts'), text);
      const offset = text.indexOf('value', text.indexOf('fetch('));
      f.query.operand.start.byte_offset = offset;
      f.query.operand.end.byte_offset = offset + 5;
      const unsupported = collect(f.request).observations[0].facts;
      assert.ok(!unsupported.some(v => v.kind === 'local_call_argument'));
      assert.ok(unsupported.some(v => v.remaining_checks.includes('argument_mapping_incomplete')));
    }
    const spread = `export function target(value: string) { return fetch(value); }
      const parts: [string] = ['candidate']; target(...parts);`;
    fs.writeFileSync(path.join(f.root, 'app.ts'), spread);
    const offset = spread.indexOf('value', spread.indexOf('fetch('));
    f.query.operand.start.byte_offset = offset;
    f.query.operand.end.byte_offset = offset + 5;
    const unsupported = collect(f.request).observations[0].facts;
    assert.ok(!unsupported.some(v => v.kind === 'local_call_argument'));
    assert.ok(unsupported.some(v => v.remaining_checks.includes('argument_mapping_incomplete')));
    const overloaded = `export function target(value: string): unknown;
      export function target(value: string) { return fetch(value); }
      target('candidate');`;
    fs.writeFileSync(path.join(f.root, 'app.ts'), overloaded);
    const position = overloaded.indexOf('value', overloaded.indexOf('fetch('));
    f.query.operand.start.byte_offset = position;
    f.query.operand.end.byte_offset = position + 5;
    const overloadFacts = collect(f.request).observations[0].facts;
    assert.ok(!overloadFacts.some(v => v.kind === 'local_call_argument'));
    assert.ok(overloadFacts.some(v => v.value === 'observed_parameter_callers:0;indexed_calls:0'));
  } finally { f.cleanup(); }
});

test('real compiler resolves renamed cross-file helper and exact Unicode source ranges in TS, TSX and JS', () => {
  for (const extension of ['ts', 'tsx', 'js']) {
    const f = fixture(extension);
    try {
      const snapshot = collect(f.request);
      assert.match(snapshot.backend, /^typescript:5\.9\.3$/);
      assert.equal(snapshot.observations.length, 1);
      const facts = snapshot.observations[0].facts;
      assert.ok(facts.some(value => value.kind === 'semantic_definition' && value.location.path === 'helpers.ts' && value.value === 'makePath'));
      const returned = facts.find(value => value.kind === 'local_operand_origin' && value.location.path === 'helpers.ts');
      assert.equal(returned.value, '"storage/" + value');
      assert.ok(returned.remaining_checks.includes('runtime_dispatch_not_proven'));
      assert.ok(facts.some(value => value.kind === 'local_call_argument' && value.value === 'input'));
      for (const fact of facts) {
        const bytes = fs.readFileSync(path.join(f.root, fact.location.path));
        const start = fact.location.start.byte_offset;
        const prefix = bytes.subarray(0, start).toString('utf8');
        assert.equal(fact.location.start.line, prefix.split('\n').length);
        assert.equal(fact.location.start.column, Buffer.byteLength(prefix.slice(prefix.lastIndexOf('\n') + 1)) + 1);
        if (['local_operand_origin', 'local_call_argument'].includes(fact.kind)) {
          assert.equal(bytes.subarray(start, fact.location.end.byte_offset).toString('utf8'), fact.value);
        }
      }
    } finally { f.cleanup(); }
  }
});

test('any and declared interfaces stay unresolved or navigation without helper implementation', () => {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.root, 'helpers.ts'), 'export declare function makePath(value: string): any;');
    const snapshot = collect(f.request);
    assert.ok(snapshot.observations[0].facts.some(value => value.kind === 'operand_boundary' && value.value === 'unresolved_or_dynamic_type'));
    assert.ok(!snapshot.observations[0].facts.some(value => value.kind === 'local_operand_origin'));
  } finally { f.cleanup(); }
});

test('mutated object contents and branched helpers do not become fixed-value proofs', () => {
  const f = fixture();
  try {
    const source = 'export function run(input: string) { const holder = {value: "fixed"}; holder.value = input; return readFileSync(holder.value); }';
    fs.writeFileSync(path.join(f.root, 'app.ts'), source);
    const start = source.indexOf('holder.value', source.indexOf('return readFileSync'));
    f.query.operand.start.byte_offset = start;
    f.query.operand.end.byte_offset = start + 'holder.value'.length;
    const facts = collect(f.request).observations[0].facts;
    assert.ok(facts.some(fact => fact.kind === 'semantic_definition'));
    assert.ok(!facts.some(fact => fact.kind === 'local_operand_origin'));
    assert.ok(facts.every(fact => fact.remaining_checks.length > 0));
    fs.writeFileSync(path.join(f.root, 'helpers.ts'), 'export function makePath(value: string) { if (value.length) return value; return "fixed"; }');
    const second = fixture();
    try {
      fs.copyFileSync(path.join(f.root, 'helpers.ts'), path.join(second.root, 'helpers.ts'));
      assert.ok(!collect(second.request).observations[0].facts.some(fact => fact.kind === 'local_operand_origin'));
    } finally { second.cleanup(); }
  } finally { f.cleanup(); }
});

test('HTML origins locate DOM receivers and dynamic formatter bindings without safety proofs', () => {
  const f = fixture();
  try {
    for (const [source, operand, origins] of [
      ['const button = document.querySelector("[data-theme]"); const icon = button?.querySelector(".icon"); document.body.innerHTML = icon.innerHTML;', 'icon.innerHTML', ['button?.querySelector(".icon")', 'document.querySelector("[data-theme]")']],
      ['const P = (window as any).Prism; const language = P.highlight(input, P.languages.javascript); document.body.innerHTML = language;', 'language', ['P.highlight(input, P.languages.javascript)', '(window as any).Prism']],
      ['const holder = { html: "fixed" }; holder.html = input; document.body.innerHTML = holder.html;', 'holder.html', ['{ html: "fixed" }']],
      ['let html = "fixed"; html = input; document.body.innerHTML = html;', 'html', []],
    ]) {
      fs.writeFileSync(path.join(f.root, 'app.ts'), source);
      const start = source.lastIndexOf(operand);
      f.query.role = 'content';
      f.query.operand.start.byte_offset = start;
      f.query.operand.end.byte_offset = start + operand.length;
      const facts = collect(f.request).observations[0].facts;
      const navigated = facts.filter(v => v.remaining_checks.includes('source_initializer_navigation'));
      assert.deepEqual(navigated.map(v => v.value), origins);
      assert.ok(navigated.every(v => v.remaining_checks.includes('receiver_contents_and_writers_not_proven')));
      assert.ok(!facts.some(v => v.kind === 'fixed_filesystem_path'));
      for (const fact of navigated) {
        assert.equal(Buffer.from(source).subarray(fact.location.start.byte_offset, fact.location.end.byte_offset).toString(), fact.value);
      }
    }
  } finally { f.cleanup(); }
});

test('HTML origin navigation stops at bounded aliases and oversized initializers', () => {
  const f = fixture();
  try {
    for (const [source, count] of [
      ['const a = input; const b = a; const c = b; const d = c; document.body.innerHTML = d;', 3],
      [`const html = "${'x'.repeat(1100)}"; document.body.innerHTML = html;`, 0],
    ]) {
      fs.writeFileSync(path.join(f.root, 'app.ts'), source);
      const operand = source.endsWith('= d;') ? 'd' : 'html';
      const start = source.lastIndexOf(operand);
      f.query.role = 'content';
      f.query.operand.start.byte_offset = start;
      f.query.operand.end.byte_offset = start + operand.length;
      const facts = collect(f.request).observations[0].facts;
      assert.equal(facts.filter(v => v.remaining_checks.includes('source_initializer_navigation')).length, count);
    }
  } finally { f.cleanup(); }
});

test('snapshot binds source, compiler, package metadata and missing import resolution probes', () => {
  const f = fixture();
  try {
    const snapshot = collect(f.request);
    assert.ok(snapshot.inputs.some(value => value.path.replaceAll('\\', '/') === compiler.replaceAll('\\', '/')));
    assert.ok(snapshot.inputs.some(value => value.path.endsWith('/lib.es2022.d.ts')));
    assert.ok(snapshot.probes.some(value => value.kind === 'file' && value.exists === false));
    assert.ok(snapshot.sources.some(value => value.path === 'helpers.ts'));
    const bad = JSON.parse(fs.readFileSync(f.context));
    bad.projects.push(bad.projects[0]);
    fs.writeFileSync(f.context, JSON.stringify(bad));
    assert.throws(() => collect(f.request), /project IDs must be unique/);
  } finally { f.cleanup(); }
});

test('tsconfig inheritance and aliases resolve with explicit source scope and bound config reads', () => {
  const f = fixture();
  try {
    fs.mkdirSync(path.join(f.root, 'config'));
    fs.writeFileSync(path.join(f.root, 'config/base.json'), '{"compilerOptions":{"baseUrl":"..","paths":{"@helpers":["helpers.ts"]}}}');
    fs.writeFileSync(path.join(f.root, 'tsconfig.json'), '{/* JSONC */"extends":"./config/base.json","include":["unrelated/**/*"]}');
    fs.writeFileSync(path.join(f.root, 'app.ts'), fs.readFileSync(path.join(f.root, 'app.ts'), 'utf8').replace('./helpers', '@helpers'));
    f.query.operand.start.byte_offset -= 1; f.query.operand.end.byte_offset -= 1;
    const context = JSON.parse(fs.readFileSync(f.context));
    context.projects[0].tsconfig = 'tsconfig.json';
    fs.writeFileSync(f.context, JSON.stringify(context));
    const snapshot = collect(f.request);
    assert.ok(snapshot.observations[0].facts.some(f => f.kind === 'semantic_definition' && f.location.path === 'helpers.ts'));
    assert.ok(snapshot.inputs.some(f => f.path.endsWith('/config/base.json')));
    assert.ok(snapshot.inputs.some(f => f.path.endsWith('/tsconfig.json')));
    fs.writeFileSync(path.join(f.root, 'tsconfig.json'), '{"extends":"./absent.json"}');
    assert.throws(() => collect(f.request), /Cannot read file/);
  } finally { f.cleanup(); }
});

test('only literal-only Node paths close traversal; inputs, shadows and overwritten APIs stay open', () => {
  const f = fixture();
  try {
    const context = JSON.parse(fs.readFileSync(f.context));
    context.node_types = nodeTypes;
    context.projects[0].compiler_options.esModuleInterop = true;
    fs.writeFileSync(f.context, JSON.stringify(context));
    fs.writeFileSync(path.join(f.root, 'helpers.ts'), 'export const fixedRoot = "storage";');
    for (const [prefix, operand, closed] of [
      ["import path from 'node:path'; import {fixedRoot} from './helpers';", "path.resolve(fixedRoot, 'fixed.txt')", true],
      ["import path from 'node:path';", "path.resolve(input, 'fixed.txt')", false],
      ["import path from 'node:path'; declare const custom: typeof path;", "custom.resolve('fixed.txt')", false],
      ["import {resolve as selected} from 'node:path';", "selected('fixed.txt')", true],
      ['const path = {resolve: (v: string) => v};', "path.resolve('fixed.txt')", false],
      ["import path from 'node:path'; path.resolve = (v: string) => v;", "path.resolve('fixed.txt')", false],
      ["import path from 'node:path'; Object.assign(path, {resolve: (v: string) => v});", "path.resolve('fixed.txt')", false],
    ]) {
      const source = `${prefix}\nexport function run(input: string) { return readFileSync(${operand}); }`;
      fs.writeFileSync(path.join(f.root, 'app.ts'), source);
      const start = source.indexOf(operand, source.indexOf('readFileSync'));
      f.query.operand.start.byte_offset = start;
      f.query.operand.end.byte_offset = start + operand.length;
      const snapshot = collect(f.request);
      assert.equal(snapshot.observations[0].facts.some(f => f.kind === 'fixed_filesystem_path'), closed, source);
      assert.ok(snapshot.inputs.some(f => f.path.endsWith('/@types/node/path.d.ts')));
    }
  } finally { f.cleanup(); }
});

test('complete static paths propagate through small source helpers, preserving dynamic and dispatch boundaries', () => {
  const f = fixture();
  try {
    const context = JSON.parse(fs.readFileSync(f.context));
    context.node_types = nodeTypes;
    fs.writeFileSync(f.context, JSON.stringify(context));
    for (const [helper, operand, closed] of [
      ['export function makePath(value: string) { return "storage/" + value; }', 'makePath("fixed.txt")', true],
      ['export const makePath = (value: string) => "storage/" + value;', 'makePath("fixed.txt")', true],
      ['export function nested(value: string) { return "storage/" + value; } export function makePath(value: string) { return nested(value); }', 'makePath("fixed.txt")', true],
      ['export function makePath(value: string) { return "storage/" + value; }', 'makePath(input)', false],
      ['export function makePath(value: string) { value = "fixed"; return value; }', 'makePath(input)', false],
      ['export function makePath(value: string) { if (value) return value; return "fixed"; }', 'makePath("fixed.txt")', false],
      ['export function makePath(value: string) { return makePath(value); }', 'makePath("fixed.txt")', false],
      ['export function makePath(value: string = "fixed") { return value; }', 'makePath()', false],
      ['export async function makePath(value: string) { return value; }', 'makePath("fixed.txt")', false],
      ['export function makePath(value: string) { return value; } makePath = (v: string) => external(v);', 'makePath("fixed.txt")', false],
    ]) {
      fs.writeFileSync(path.join(f.root, 'helpers.ts'), helper);
      const source = `import {makePath} from './helpers'; export function run(input: string) { return readFileSync(${operand}); }`;
      fs.writeFileSync(path.join(f.root, 'app.ts'), source);
      const start = source.indexOf(operand, source.indexOf('readFileSync'));
      Object.assign(f.query.operand.start, { byte_offset: start });
      Object.assign(f.query.operand.end, { byte_offset: start + operand.length });
      const facts = collect(f.request).observations[0].facts;
      assert.equal(facts.some(fact => fact.kind === 'fixed_filesystem_path'), closed, helper + ' ' + operand);
    }
  } finally { f.cleanup(); }
});

test('unqueried projects skip semantic work, but queries in imported sources remain covered and bound', () => {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.root, 'entry.ts'), "import './app';");
    fs.writeFileSync(path.join(f.root, 'unrelated.ts'), 'const failure: MissingType = absent;');
    const context = JSON.parse(fs.readFileSync(f.context));
    context.projects[0].sources = ['entry.ts'];
    context.projects.push({ id: 'unrelated', sources: ['unrelated.ts'], compiler_options: {} });
    fs.writeFileSync(f.context, JSON.stringify(context));
    const snapshot = collect(f.request);
    assert.equal(snapshot.observations.length, 1);
    assert.equal(snapshot.projects[0].semantic_analysis, 'performed');
    assert.equal(snapshot.projects[1].semantic_analysis, 'not_requested');
    assert.ok(snapshot.sources.some(source => source.path === 'unrelated.ts'));
    assert.ok(snapshot.sources.some(source => source.path === 'app.ts'));
    assert.ok(!snapshot.diagnostics.some(diagnostic => diagnostic.project_id === 'unrelated'));
  } finally { f.cleanup(); }
});
