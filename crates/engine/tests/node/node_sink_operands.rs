use mehscan_core::{Capability, EvidenceKind};
use std::{collections::BTreeSet, fs};

#[test]
fn bounded_helpers_preserve_api_identity_and_security_operand_roles() {
    let root = std::env::temp_dir().join(format!("mehscan-sink-operands-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("helpers.js"),
        r#"
import files from 'node:fs/promises';
import {readFile as load} from 'node:fs/promises';
import * as disk from 'node:fs';
import {renderString as render} from 'nunjucks';
import ejs from 'ejs';
import client from 'axios';
import {request as requestHttp} from 'node:http';
import {fetch as remote} from 'undici';
import custom from 'unrelated-files';
import cp from 'node:child_process';
import * as processes from 'child_process';
import {exec as run, spawn as start} from 'node:child_process';
import child_process from 'unrelated-processes';
const {execSync: runSync} = require('child_process');
const processModule = require('node:child_process');
const runFile = require('node:child_process').execFile;
const {readFile: cjsLoad} = require('node:fs/promises');
export function read(p) { return files.readFile(p, 'utf8'); }
export function readCjs(p) { return cjsLoad(p); }
export function readAlias(p) { return load(p); }
export function stream(p) { return disk.createReadStream(p); }
export function write(p) { return files.writeFile(p, 'constant'); }
export function payload(p) { return files.writeFile('/safe/file', p); }
export function copySource(p) { return files.copyFile(p, '/safe/out'); }
export function copyDestination(p) { return files.copyFile('/safe/in', p); }
export function copyBoth(p) { return files.copyFile(p, p); }
export function renameSource(p) { return files.rename(p, '/safe/out'); }
export function renameDestination(p) { return files.rename('/safe/in', p); }
export function remove(p) { return files.unlink(p); }
export function template(p) { return render(p, {name:'safe'}); }
export function templateData(p) { return render('Hello {{name}}', p); }
export function compile(p) { return ejs.compile(p); }
export function renderOverwrite(p) { p='safe'; return ejs.render(p); }
export function renderShadow(p, ejs) { return ejs.render(p); }
export function url(p) { return client.post(p, {safe:true}); }
export function body(p) { return client.post('https://example.org', p); }
export function optionsUrl(p) { return client.request({url:p, method:'GET'}); }
export function optionsBody(p) { return client.request({url:'https://example.org', data:p}); }
export function hostname(p) { return requestHttp({hostname:p, path:'/safe'}); }
export function fixedHostPath(p) { return requestHttp({hostname:'example.org', path:p}); }
export function ignoredHost(p) { return requestHttp({hostname:'example.org', host:p}); }
export function duplicate(p) { return client.request({url:p, url:'https://example.org'}); }
export function spread(p) { return client.request({url:p, ...defaults}); }
export function undici(p) { return remote(p); }
export function unrelated(p) { return custom.readFile(p); }
export function overwrite(p) { p='/safe'; return files.readFile(p); }
export function shadow(p, files) { return files.readFile(p); }
export function localShadow(p) { const files = custom; return files.readFile(p); }
export function fetchShadow(p) { const fetch = custom; return fetch(p); }
export function constant(p) { return load('/safe/file'); }
export function shell(p) { return cp.exec(p); }
export function shellAlias(p) { return run(p); }
export function shellNamespace(p) { return processes.execSync(p); }
export function shellCommon(p) { return runSync(p); }
export function spawnCommon(p) { return processModule.spawn(p, []); }
export function execFileCommon(p) { return runFile(p, []); }
export function spawnAlias(p) { return start(p, []); }
export function execFileSync(p) { return cp.execFileSync(p, []); }
export function spawnSync(p) { return cp.spawnSync(p, []); }
export function fork(p) { return cp.fork(p, []); }
export function argv(p) { return cp.spawn('/usr/bin/printf', [p]); }
export function options(p) { return cp.exec('date', p); }
export function processOverwrite(p) { p='date'; return cp.exec(p); }
export function processShadow(p, cp) { return cp.exec(p); }
export function processLocalShadow(p) { const cp = custom; return cp.exec(p); }
export function processRebound(p) { cp=custom; return cp.exec(p); }
export function unrelatedProcess(p) { return child_process.exec(p); }
export function spellingOnly(p) { return unbound_process.exec(p); }
"#,
    )
    .unwrap();
    let read = Capability::FilesystemRead;
    let write = Capability::FilesystemWrite;
    let template = Capability::TemplateEvaluation;
    let network = Capability::OutboundNetworkRequest;
    let process = Capability::ProcessExecution;
    let cases: &[(&str, &[Capability])] = &[
        ("read", &[read]),
        ("readCjs", &[read]),
        ("readAlias", &[read]),
        ("stream", &[read]),
        ("write", &[write]),
        ("payload", &[]),
        ("copySource", &[read]),
        ("copyDestination", &[write]),
        ("copyBoth", &[read, write]),
        ("renameSource", &[write]),
        ("renameDestination", &[write]),
        ("remove", &[write]),
        ("template", &[template]),
        ("templateData", &[]),
        ("compile", &[template]),
        ("renderOverwrite", &[]),
        ("renderShadow", &[]),
        ("url", &[network]),
        ("body", &[]),
        ("optionsUrl", &[network]),
        ("optionsBody", &[]),
        ("hostname", &[network]),
        ("fixedHostPath", &[]),
        ("ignoredHost", &[]),
        ("duplicate", &[]),
        ("spread", &[]),
        ("undici", &[network]),
        ("unrelated", &[]),
        ("overwrite", &[]),
        ("shadow", &[]),
        ("localShadow", &[]),
        ("fetchShadow", &[]),
        ("constant", &[]),
        ("shell", &[process]),
        ("shellAlias", &[process]),
        ("shellNamespace", &[process]),
        ("shellCommon", &[process]),
        ("spawnCommon", &[process]),
        ("execFileCommon", &[process]),
        ("spawnAlias", &[process]),
        ("execFileSync", &[process]),
        ("spawnSync", &[process]),
        ("fork", &[process]),
        ("argv", &[]),
        ("options", &[]),
        ("processOverwrite", &[]),
        ("processShadow", &[]),
        ("processLocalShadow", &[]),
        ("processRebound", &[]),
        ("unrelatedProcess", &[]),
        ("spellingOnly", &[]),
    ];
    for (index, (name, _)) in cases.iter().enumerate() {
        let extension = ["js", "ts", "tsx"][index % 3];
        let annotation = if extension == "js" { "" } else { ":any" };
        fs::write(root.join(format!("{name}.{extension}")), format!(
            "import {{{name}}} from './helpers.js'; export function handle(req{annotation}) {{ return {name}(req.query.value); }}"
        )).unwrap();
    }
    fs::write(root.join("clean.js"), "import {read,shell,spawnAlias} from './helpers.js'; export function handle(req) { read('/safe/file'); shell('date'); spawnAlias('/usr/bin/printf'); }").unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (index, (name, expected)) in cases.iter().enumerate() {
        let path = format!("{name}.{}", ["js", "ts", "tsx"][index % 3]);
        let summaries = scan
            .evidence
            .iter()
            .filter(|e| {
                e.location.path == path
                    && e.kind == EvidenceKind::Sink
                    && e.rule_id.contains("parameter-sink-summary")
            })
            .collect::<Vec<_>>();
        let actual = summaries
            .iter()
            .map(|e| format!("{:?}", e.capability))
            .collect::<BTreeSet<_>>();
        let expected = expected
            .iter()
            .map(|c| format!("{c:?}"))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected, "wrong sink operands in {path}");
        for summary in summaries {
            assert!(
                summary
                    .tags
                    .iter()
                    .any(|t| t == "review-admission:source-sink-required")
            );
            assert!(
                scan.security_paths.iter().any(|p| p
                    .steps
                    .last()
                    .is_some_and(|s| s.evidence_id.as_deref() == Some(summary.id.as_str()))),
                "no bounded source flow for {path}"
            );
        }
    }
    assert!(!scan.security_paths.iter().any(|p| {
        p.steps
            .last()
            .is_some_and(|s| s.location.path == "clean.js")
    }));
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    assert!(
        !inventory.entries.iter().any(|e| e.path == "clean.js"),
        "a constant helper call must not reopen a sink-only review"
    );
    for (name, operand) in [
        ("copySource", "source_path"),
        ("copyDestination", "destination_path"),
        ("renameSource", "source_path"),
        ("renameDestination", "destination_path"),
        ("shellAlias", "command"),
        ("spawnAlias", "executable"),
        ("execFileCommon", "executable"),
        ("fork", "module_path"),
    ] {
        assert!(scan.evidence.iter().any(|e| {
            e.location.path.starts_with(&format!("{name}."))
                && e.tags
                    .iter()
                    .any(|t| t == &format!("helper-operand:{operand}"))
        }));
    }
    fs::remove_dir_all(root).unwrap();
}
