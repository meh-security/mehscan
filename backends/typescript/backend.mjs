// Source-only compiler facts for selected operands. Never emit or execute target code.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const absolute = value => path.resolve(value).replaceAll('\\', '/');
const MAX_FILE = 2 * 1024 * 1024;

export function collect(request) {
  if (request.schema_version !== '1') throw Error('Unsupported TypeScript request');
  const root = absolute(fs.realpathSync(request.root));
  const contextBytes = fs.readFileSync(request.context_path);
  const context = JSON.parse(contextBytes);
  const compilerPath = absolute(context.typescript_path);
  if (!path.isAbsolute(context.typescript_path)) throw Error('typescript_path must be absolute');
  const ts = createRequire(import.meta.url)(compilerPath);
  const inputs = new Map([[compilerPath, hash(fs.readFileSync(compilerPath))]]);
  const probes = new Map();
  const sources = new Map();
  const projects = [];
  const observations = [];
  const diagnostics = [];
  const ids = new Set();
  function read(file) {
    const key = absolute(file);
    try {
      const bytes = fs.readFileSync(key);
      if (bytes.length > MAX_FILE) throw Error(`TypeScript input exceeds 2 MiB: ${key}`);
      inputs.set(key, hash(bytes));
      return bytes.toString('utf8');
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
      probes.set(`file:${key}`, { kind: 'file', path: key, exists: false });
      return undefined;
    }
  }
  if (context.node_types && !path.isAbsolute(context.node_types)) throw Error('node_types must be absolute');
  const nodeTypes = context.node_types && absolute(fs.realpathSync(context.node_types));
  if (nodeTypes && JSON.parse(read(path.join(nodeTypes, 'package.json'))).name !== '@types/node') {
    throw Error('node_types must identify the supplied @types/node package');
  }
  const inside = file => absolute(file).startsWith(root + '/');
  const relative = file => path.relative(root, file).replaceAll('\\', '/');
  function location(node) {
    const source = node.getSourceFile();
    if (!inside(source.fileName)) return undefined;
    function at(offset) {
      const prefix = source.text.slice(0, offset);
      return { line: prefix.split('\n').length,
        column: Buffer.byteLength(prefix.slice(prefix.lastIndexOf('\n') + 1)) + 1,
        byte_offset: Buffer.byteLength(prefix) };
    }
    return { path: relative(source.fileName), start: at(node.getStart(source)), end: at(node.end) };
  }
  function fact(node, kind, role, value, checks = ['exact_interpretation_and_effect', 'runtime_dispatch_not_proven']) {
    const where = location(node);
    return where && { kind, role, location: where, value, remaining_checks: checks };
  }
  for (const project of context.projects ?? []) {
    if (!project.id || ids.has(project.id)) throw Error('TypeScript project IDs must be unique');
    ids.add(project.id);
    if (project.runtime !== undefined && !['browser', 'server'].includes(project.runtime)) throw Error('runtime must be browser or server');
    const converted = ts.convertCompilerOptionsFromJson(project.compiler_options ?? {}, root);
    if (converted.errors.length) throw Error(ts.flattenDiagnosticMessageText(converted.errors[0].messageText, '\n'));
    let configured = {};
    if (project.tsconfig) {
      if (path.isAbsolute(project.tsconfig) || project.tsconfig.split(/[\\/]/).includes('..')) throw Error('tsconfig must be repository-relative');
      const config = ts.getParsedCommandLineOfConfigFile(path.join(root, project.tsconfig), undefined, {
        ...ts.sys, readFile: read, getCurrentDirectory: () => root,
        // Explicit source scope replaces config glob discovery; do not load unrelated projects.
        readDirectory: () => [],
        onUnRecoverableConfigFileDiagnostic: d => { throw Error(ts.flattenDiagnosticMessageText(d.messageText, '\n')); }
      });
      const invalid = config?.errors.filter(d => ![18002, 18003].includes(d.code));
      if (!config || invalid.length) throw Error(invalid?.map(d => ts.flattenDiagnosticMessageText(d.messageText, '\n')).join('\n') || 'Cannot read tsconfig');
      if (config.projectReferences?.length) throw Error('tsconfig project references are unsupported; supply explicit compiler_options and separate source contexts');
      configured = config.options;
    }
    const options = { ...configured, ...converted.options, noEmit: true, incremental: false, composite: false };
    const names = project.sources.map(file => {
      if (path.isAbsolute(file) || file.split(/[\\/]/).includes('..')) throw Error('Sources must be repository-relative');
      const full = absolute(fs.realpathSync(path.join(root, file)));
      if (!inside(full)) throw Error('Source escapes repository root');
      return full;
    });
    if (nodeTypes) names.push(path.join(nodeTypes, 'index.d.ts'));
    const host = ts.createCompilerHost(options, true);
    host.readFile = read;
    host.getCurrentDirectory = () => root;
    host.writeFile = () => { throw Error('Target emit is disabled'); };
    host.getSourceFile = (file, language) => {
      const text = read(file);
      return text === undefined ? undefined : ts.createSourceFile(file, text, language, true);
    };
    host.fileExists = file => {
      const key = absolute(file);
      const exists = ts.sys.fileExists(key);
      probes.set(`file:${key}`, { kind: 'file', path: key, exists });
      return exists;
    };
    host.directoryExists = directory => {
      const key = absolute(directory);
      const exists = ts.sys.directoryExists(key);
      probes.set(`directory:${key}`, { kind: 'directory', path: key, exists });
      return exists;
    };
    host.getDirectories = directory => {
      const key = absolute(directory);
      const directories = ts.sys.getDirectories(key);
      const children = directories.map(child => absolute(path.isAbsolute(child) ? child : path.join(key, child))).sort();
      probes.set(`children:${key}`, { kind: 'children', path: key, children });
      return directories;
    };
    const program = ts.createProgram(names, options, host);
    const localSources = new Map();
    for (const source of program.getSourceFiles()) {
      if (inside(source.fileName)) {
        const name = relative(source.fileName);
        sources.set(name, hash(Buffer.from(source.text)));
        localSources.set(name, source);
      }
    }
    const projectQueries = request.queries.filter(query => localSources.has(query.operand.path));
    // Follow imports before deciding relevance: an operand may belong to a source
    // dependency rather than an explicitly supplied entry. Bind those reads even
    // when skipping expensive semantic diagnostics for an unqueried project.
    if (!projectQueries.length) {
      projects.push({ id: project.id, compiler_errors: 0, semantic_analysis: 'not_requested' });
      continue;
    }
    const checker = program.getTypeChecker();
    const errors = [...program.getOptionsDiagnostics(), ...program.getGlobalDiagnostics(),
      ...program.getSyntacticDiagnostics(), ...program.getSemanticDiagnostics()]
      .filter(d => d.category === ts.DiagnosticCategory.Error);
    projects.push({ id: project.id, compiler_errors: errors.length, semantic_analysis: 'performed' });
    // Keep diagnostic output compact, while counting every error.
    for (const error of errors.slice(0, 12)) diagnostics.push({ project_id: project.id,
      code: error.code, path: error.file && inside(error.file.fileName) ? relative(error.file.fileName) : undefined,
      message: ts.flattenDiagnosticMessageText(error.messageText, '\n') });
    function symbol(node) {
      let value = checker.getSymbolAtLocation(node);
      const seen = new Set();
      while (value && value.flags & ts.SymbolFlags.Alias) {
        if (seen.has(value)) return undefined;
        seen.add(value);
        value = checker.getAliasedSymbol(value);
      }
      return value;
    }
    function declarationFacts(node, role, output) {
      const target = ts.isPropertyAccessExpression(node) ? node.name : node;
      const value = symbol(target);
      const type = checker.getTypeAtLocation(node);
      const dynamic = type.flags & (ts.TypeFlags.Any | ts.TypeFlags.Unknown);
      if (dynamic) {
        const stop = fact(node, 'operand_boundary', role, 'unresolved_or_dynamic_type', ['implementation_and_value_producer']);
        if (stop) output.push(stop);
      }
      const declarations = value?.declarations ?? [];
      const origins = [...new Set(declarations.map(declaration => {
        const file = declaration.getSourceFile().fileName;
        return inside(file) ? relative(file) : `external:${path.basename(file)}`;
      }))].slice(0, 2).join(',');
      const typeName = checker.typeToString(type).replaceAll(root + '/', '').slice(0, 1000);
      const identity = !dynamic && fact(node, 'semantic_identity', role,
        `typescript:${value?.getName() ?? 'expression'};declarations=${origins};type=${typeName}`);
      if (identity) output.push(identity);
      for (const declaration of declarations.slice(0, 2)) {
        const name = declaration.name ?? declaration;
        const located = fact(name, 'semantic_definition', role, value.getName(), ['declaration_is_not_runtime_implementation', 'exact_interpretation_and_effect']);
        if (located) output.push(located);
      }
    }
    function helperReturn(call, role, output) {
      const signature = checker.getResolvedSignature(call);
      const declaration = signature?.declaration;
      if (!declaration?.body || declaration.getWidth() > 8192
        || !(ts.isFunctionDeclaration(declaration) || ts.isFunctionExpression(declaration) || ts.isArrowFunction(declaration))) return;
      const body = declaration.body;
      const expression = !ts.isBlock(body) ? body
        : body.statements.length === 1 && ts.isReturnStatement(body.statements[0]) ? body.statements[0].expression : undefined;
      if (!expression || !inside(expression.getSourceFile().fileName)) return;
      const result = fact(expression, 'local_operand_origin', role, expression.getText(),
        ['source_helper_return_navigation', 'argument_mapping_and_mutation', 'runtime_dispatch_not_proven', 'exact_interpretation_and_effect']);
      if (result) output.push(result);
      for (let index = 0; index < Math.min(call.arguments.length, declaration.parameters.length, 4); index++) {
        const argument = call.arguments[index];
        const mapped = fact(argument, 'local_call_argument', role, argument.getText(),
          [`helper_parameter:${declaration.parameters[index].name.getText()}`, 'default_rest_and_runtime_dispatch', 'exact_interpretation_and_effect']);
        if (mapped) output.push(mapped);
      }
    }
    // HTML producer navigation, including a copied DOM receiver or a formatter
    // held in a local binding. Initializers locate research, never prove values.
    function contentOrigins(node, output, seen = new Set(), depth = 0) {
      if (!node || depth > 2) return;
      if (ts.isParenthesizedExpression(node) || ts.isAsExpression(node)
        || ts.isTypeAssertionExpression(node) || ts.isNonNullExpression(node)) {
        contentOrigins(node.expression, output, seen, depth);
      } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
        contentOrigins(node.expression, output, seen, depth);
      } else if (ts.isCallExpression(node)) {
        helperReturn(node, 'content', output);
        contentOrigins(node.expression, output, seen, depth);
      } else if (ts.isIdentifier(node)) {
        const value = symbol(node);
        if (!value || seen.has(value)) return;
        seen.add(value);
        const declarations = value.declarations ?? [];
        if (declarations.length !== 1 || !ts.isVariableDeclaration(declarations[0])) return;
        const declaration = declarations[0];
        const initializer = declaration.initializer;
        if (!initializer || !(declaration.parent.flags & ts.NodeFlags.Const)
          || Buffer.byteLength(initializer.getText()) > 1024) return;
        const origin = fact(initializer, 'local_operand_origin', 'content', initializer.getText(),
          ['source_initializer_navigation', 'const_binding_not_deep_immutability',
            'receiver_contents_and_writers_not_proven', 'exact_interpretation_and_effect']);
        if (origin) {
          const existing = output.find(value => value.kind === origin.kind && value.role === origin.role
            && value.location.path === origin.location.path
            && value.location.start.byte_offset === origin.location.start.byte_offset
            && value.location.end.byte_offset === origin.location.end.byte_offset);
          if (existing) existing.remaining_checks = [...new Set([...existing.remaining_checks, ...origin.remaining_checks])];
          else output.push(origin);
        }
        contentOrigins(initializer, output, seen, depth + 1);
      }
    }
    // Incoming argument navigation is cached once per supplied project. It is
    // an observed signature edge, never a caller-completeness or value proof.
    let incomingCalls;
    let incomingTruncated = false;
    function parameterArguments(node, role, output) {
      const declarations = symbol(node)?.declarations;
      if (declarations?.length !== 1 || !ts.isParameter(declarations[0])) return;
      const parameter = declarations[0];
      const owner = parameter.parent;
      if (!owner.body || !owner.parameters || !ts.isIdentifier(parameter.name)) return;
      const index = owner.parameters.indexOf(parameter);
      if (!incomingCalls) {
        incomingCalls = new Map();
        let visits = 0;
        let calls = 0;
        for (const source of localSources.values()) {
          function visit(current) {
            if (incomingTruncated) return;
            if (++visits > 200000) { incomingTruncated = true; return; }
            if (ts.isCallExpression(current) || ts.isNewExpression(current)) {
              if (++calls > 20000) { incomingTruncated = true; return; }
              const target = checker.getResolvedSignature(current)?.declaration;
              if (target?.body && inside(target.getSourceFile().fileName)) {
                let entry = incomingCalls.get(target);
                if (!entry) incomingCalls.set(target, entry = { count: 0, calls: [] });
                entry.count++;
                if (entry.calls.length < 8) entry.calls.push(current);
              }
            }
            ts.forEachChild(current, visit);
          }
          visit(source);
        }
      }
      const entry = incomingCalls.get(owner);
      let returned = 0;
      for (const call of entry?.calls ?? []) {
        const argument = call.arguments?.[index];
        // Defaults, rest and spread require mapping that this slice does not do.
        if (!argument || parameter.initializer || parameter.dotDotDotToken
          || call.arguments.slice(0, index + 1).some(ts.isSpreadElement)
          || argument.getWidth() > 1024) continue;
        const edge = fact(argument, 'local_call_argument', role, argument.getText(),
          [`callee_parameter:${parameter.name.text}`, 'observed_signature_argument',
            'caller_scope_is_supplied_project', 'parameter_writes_and_runtime_dispatch_not_proven',
            'exact_interpretation_and_effect']);
        if (edge) { output.push(edge); returned++; }
      }
      const checks = ['caller_scope_is_supplied_project', 'unobserved_callers_and_parameter_writes',
        'exact_interpretation_and_effect'];
      if (incomingTruncated) checks.push('caller_index_truncated');
      if (entry?.count > 8) checks.push('caller_locations_truncated');
      if (returned < Math.min(entry?.count ?? 0, 8)) checks.push('argument_mapping_incomplete');
      output.push(fact(parameter.name, 'operand_boundary', role,
        `observed_parameter_callers:${returned};indexed_calls:${entry?.count ?? 0}`, checks));
    }
    // A narrow value proof, not a type proof: only source literals/consts and
    // literal-only calls to the supplied Node path implementation contract.
    const mutations = new Set();
    for (const source of localSources.values()) {
      function visit(node) {
        if (ts.isBinaryExpression(node) && node.operatorToken.kind >= ts.SyntaxKind.FirstAssignment
          && node.operatorToken.kind <= ts.SyntaxKind.LastAssignment) {
          const target = ts.isPropertyAccessExpression(node.left) ? node.left.name : node.left;
          const changed = symbol(target);
          if (changed) mutations.add(changed);
          if (ts.isElementAccessExpression(node.left)) {
            const type = checker.getTypeAtLocation(node.left.expression);
            for (const property of type.getProperties()) mutations.add(property);
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(source);
    }
    function nodePathBinding(node, seen = new Set()) {
      if (ts.isPropertyAccessExpression(node) && ['posix', 'win32', 'resolve', 'join', 'normalize', 'basename', 'dirname'].includes(node.name.text)) {
        if (mutations.has(symbol(node.name))) return false;
        return nodePathBinding(node.expression, seen);
      }
      if (!ts.isIdentifier(node)) return false;
      const raw = checker.getSymbolAtLocation(node);
      if (!raw || seen.has(raw) || raw.declarations?.length !== 1 || mutations.has(symbol(node))) return false;
      const declaration = raw.declarations[0];
      if (ts.isVariableDeclaration(declaration) && declaration.initializer && declaration.parent.flags & ts.NodeFlags.Const) {
        return nodePathBinding(declaration.initializer, new Set([...seen, raw]));
      }
      if (!(ts.isImportSpecifier(declaration) || ts.isImportClause(declaration) || ts.isNamespaceImport(declaration)) || declaration.isTypeOnly) return false;
      let imported = declaration;
      while (imported && !ts.isImportDeclaration(imported)) imported = imported.parent;
      return imported && !imported.importClause?.isTypeOnly && ts.isStringLiteral(imported.moduleSpecifier)
        && ['path', 'node:path'].includes(imported.moduleSpecifier.text);
    }
    // Passing the module object to other code allows it to replace the API.
    // Do not assume a helper preserves that object, even with a matching type.
    for (const source of localSources.values()) {
      function visit(node) {
        if (ts.isCallExpression(node)) for (const argument of node.arguments) {
          if (nodePathBinding(argument)) {
            for (const property of checker.getTypeAtLocation(argument).getProperties()) mutations.add(property);
            const escaped = symbol(argument);
            if (escaped) mutations.add(escaped);
          }
        }
        ts.forEachChild(node, visit);
      }
      visit(source);
    }
    function fixedPath(node, seen = new Set(), depth = 0, argumentsBySymbol = new Map()) {
      if (depth > 12) return false;
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return true;
      if (ts.isParenthesizedExpression(node)) return fixedPath(node.expression, seen, depth + 1, argumentsBySymbol);
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken) {
        return fixedPath(node.left, seen, depth + 1, argumentsBySymbol) && fixedPath(node.right, seen, depth + 1, argumentsBySymbol);
      }
      if (ts.isIdentifier(node)) {
        const value = symbol(node);
        if (argumentsBySymbol.has(value)) return argumentsBySymbol.get(value);
        if (!value || mutations.has(value) || seen.has(value) || value.declarations?.length !== 1) return false;
        const declaration = value.declarations[0];
        if (!ts.isVariableDeclaration(declaration) || !declaration.initializer
          || !(declaration.parent.flags & ts.NodeFlags.Const) || !inside(declaration.getSourceFile().fileName)) return false;
        return fixedPath(declaration.initializer, new Set([...seen, value]), depth + 1, argumentsBySymbol);
      }
      if (!ts.isCallExpression(node)) return false;
      // Only direct compiler-bound source functions. Single-expression returns
      // can propagate complete static construction, never an arbitrary helper name.
      if (ts.isIdentifier(node.expression)) {
        const binding = symbol(node.expression);
        const declaration = checker.getResolvedSignature(node)?.declaration;
        const owner = declaration && (ts.isFunctionDeclaration(declaration) ? declaration : declaration.parent);
        const stable = owner && (ts.isFunctionDeclaration(owner)
          || ts.isVariableDeclaration(owner) && owner.parent.flags & ts.NodeFlags.Const);
        if (binding && !mutations.has(binding) && !seen.has(binding) && stable
          && declaration.body && declaration.getWidth() <= 8192
          && inside(declaration.getSourceFile().fileName)
          && !declaration.asteriskToken && !declaration.modifiers?.some(m => m.kind === ts.SyntaxKind.AsyncKeyword)
          && declaration.parameters.length === node.arguments.length
          && declaration.parameters.every(p => ts.isIdentifier(p.name) && !p.initializer && !p.dotDotDotToken)) {
          const body = declaration.body;
          const returned = !ts.isBlock(body) ? body : body.statements.length === 1
            && ts.isReturnStatement(body.statements[0]) ? body.statements[0].expression : undefined;
          if (returned) {
            const mapped = new Map(argumentsBySymbol);
            declaration.parameters.forEach((parameter, index) => mapped.set(symbol(parameter.name),
              fixedPath(node.arguments[index], seen, depth + 1, argumentsBySymbol)));
            return fixedPath(returned, new Set([...seen, binding]), depth + 1, mapped);
          }
        }
      }
      if (!nodeTypes || node.arguments.length === 0) return false;
      if (!nodePathBinding(ts.isPropertyAccessExpression(node.expression) ? node.expression.expression : node.expression)) return false;
      const callee = ts.isPropertyAccessExpression(node.expression) ? node.expression.name : node.expression;
      const value = symbol(callee);
      if (!value || mutations.has(value) || !['resolve', 'join', 'normalize', 'basename', 'dirname'].includes(value.getName())
        || !value.declarations?.length || value.declarations.some(d => absolute(d.getSourceFile().fileName) !== nodeTypes + '/path.d.ts')) return false;
      return node.arguments.every(argument => fixedPath(argument, seen, depth + 1, argumentsBySymbol));
    }
    function browserFetchShape(call) {
      if (project.runtime !== 'browser' || !ts.isCallExpression(call)
        || !ts.isIdentifier(call.expression) || call.expression.text !== 'fetch') return undefined;
      const binding = symbol(call.expression);
      if (!binding?.declarations?.length || mutations.has(binding)
        || binding.declarations.some(d => absolute(d.getSourceFile().fileName) !== absolute(fs.realpathSync(path.join(path.dirname(compilerPath), 'lib.dom.d.ts'))))) return undefined;
      if (call.arguments.length === 1) return 'ordinary_get_head';
      if (call.arguments.length !== 2 || !ts.isObjectLiteralExpression(call.arguments[1])) return 'request_options_require_review';
      // Keep headers, credentials, body, unknown options and state-changing methods active.
      const options = call.arguments[1].properties;
      return (options.length === 0 || (options.length === 1 && ts.isPropertyAssignment(options[0])
        && (ts.isIdentifier(options[0].name) || ts.isStringLiteral(options[0].name))
        && options[0].name.text === 'method' && ts.isStringLiteral(options[0].initializer)
        && ['GET', 'HEAD'].includes(options[0].initializer.text.toUpperCase()))) ? 'ordinary_get_head' : 'request_options_require_review';
    }
    for (const query of projectQueries) {
      const source = localSources.get(query.operand.path);
      if (!source) continue;
      const bytes = Buffer.from(source.text);
      const start = bytes.subarray(0, query.operand.start.byte_offset).toString('utf8').length;
      const end = bytes.subarray(0, query.operand.end.byte_offset).toString('utf8').length;
      let operand;
      let visits = 0;
      function find(node) {
        if (++visits > 200000) return;
        if (node.getStart(source) > start || node.end < end) return;
        if (node.getStart(source) === start && node.end === end && ts.isExpressionNode(node)) operand = node;
        ts.forEachChild(node, find);
      }
      find(source);
      const facts = [];
      if (!operand) continue;
      if (query.role === 'path' && nodeTypes && fixedPath(operand)) {
        facts.push(fact(operand, 'fixed_filesystem_path', 'path', operand.getText(),
          ['complete_static_path_operand', 'supplied_node_path_contract', 'filesystem_effect_and_authority']));
      }
      declarationFacts(operand, query.role, facts);
      let sink = operand.parent;
      while (sink && !ts.isCallExpression(sink) && !ts.isNewExpression(sink) && !ts.isSourceFile(sink)) sink = sink.parent;
      const browserShape = query.role === 'endpoint' && browserFetchShape(sink);
      if (browserShape && sink.arguments[0] === operand) {
        facts.push(fact(operand, 'browser_request_context', 'endpoint', operand.getText(),
          ['explicit_browser_runtime', 'dom_fetch_binding', browserShape, 'destination_authority_and_consequential_effects']));
      }
      if (sink && (ts.isCallExpression(sink) || ts.isNewExpression(sink))) declarationFacts(sink.expression, 'operation', facts);
      if (ts.isCallExpression(operand)) {
        declarationFacts(operand.expression, query.role, facts);
        helperReturn(operand, query.role, facts);
      } else if (ts.isIdentifier(operand)) {
        parameterArguments(operand, query.role, facts);
        const declarations = symbol(operand)?.declarations ?? [];
        if (declarations.length === 1 && ts.isVariableDeclaration(declarations[0]) && declarations[0].initializer) {
          const declaration = declarations[0];
          if (declaration.parent.flags & ts.NodeFlags.Const) {
            const origin = fact(declaration.initializer, 'local_operand_origin', query.role, declaration.initializer.getText(),
              ['const_binding_not_deep_immutability', 'captured_or_mutated_contents', 'exact_interpretation_and_effect']);
            if (origin) facts.push(origin);
            if (ts.isCallExpression(declaration.initializer)) {
              declarationFacts(declaration.initializer.expression, query.role, facts);
              helperReturn(declaration.initializer, query.role, facts);
            }
          }
        }
      }
      if (query.role === 'content') contentOrigins(operand, facts);
      observations.push({ evidence_id: query.evidence_id, project_id: project.id,
        facts: [...new Map(facts.map(value => [JSON.stringify(value), value])).values()] });
    }
  }
  if (!projects.length) throw Error('Context requires projects');
  // The compiler entry and adjacent package metadata bind the selected compiler.
  const packageFile = path.resolve(path.dirname(compilerPath), '../package.json');
  if (fs.existsSync(packageFile)) inputs.set(absolute(packageFile), hash(fs.readFileSync(packageFile)));
  for (const file of context.context_files ?? []) {
    if (!path.isAbsolute(file)) throw Error('context_files must be absolute');
    read(file);
    if (!inputs.has(absolute(file))) throw Error(`Missing context file: ${file}`);
  }
  return { schema_version: '1', backend: `typescript:${ts.version}`, context_sha256: hash(contextBytes),
    sources: [...sources].map(([path, sha256]) => ({ path, sha256 })),
    inputs: [...inputs].map(([path, sha256]) => ({ path, sha256 })),
    probes: [...probes.values()], projects, observations, diagnostics };
}

if (process.argv[1] && absolute(process.argv[1]) === absolute(fileURLToPath(import.meta.url))) {
  try {
    const request = fs.readFileSync(0, 'utf8');
    if (Buffer.byteLength(request) > 8 * 1024 * 1024) throw Error('Request exceeds 8 MiB');
    const result = JSON.stringify(collect(JSON.parse(request)));
    if (Buffer.byteLength(result) > 8 * 1024 * 1024) throw Error('Snapshot exceeds 8 MiB; narrow context');
    process.stdout.write(result);
  } catch (error) { process.stderr.write(error.message + '\n'); process.exitCode = 1; }
}
