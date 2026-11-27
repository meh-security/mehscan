use mehscan_core::Capability;
use std::fs;

#[test]
fn summaries_use_exact_source_files_for_values_callbacks_and_adapters() {
    let root = std::env::temp_dir().join(format!("mehscan-summary-owners-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for (name, source) in [
        (
            "returns/helper.ts",
            "export function take(value) { return value; } export async function later(value) { return value; }",
        ),
        (
            "returns/helper.cjs",
            "function take(value){return 'safe';} async function later(value){return 'safe';} module.exports={take,later};",
        ),
        (
            "returns/positive.ts",
            "import cp from 'node:child_process'; import {take,later} from './helper.js'; import {callbackify} from 'node:util'; const adapted=callbackify(later); export function handle(req:any) { cp.exec(take(req.query.command)); adapted(req.query.command,(err,value)=>eval(value)); }",
        ),
        (
            "returns/negative.js",
            "const cp=require('node:child_process'); const {take,later}=require('./helper.cjs'); const {callbackify}=require('node:util'); const adapted=callbackify(later); function handle(req) { cp.exec(take(req.query.command)); adapted(req.query.command,(err,value)=>eval(value)); }",
        ),
        (
            "callbacks/helper.ts",
            "export function pass(value,cb) { cb(null,value); }",
        ),
        (
            "callbacks/helper.cjs",
            "function pass(value,cb){cb(null,'safe');} module.exports={pass};",
        ),
        (
            "callbacks/positive.ts",
            "import {pass} from './helper.js'; import {promisify} from 'node:util'; const adapted=promisify(pass); export function handle(req:any) { pass(req.query.command,(err,value)=>eval(value)); adapted(req.query.command).then(value=>eval(value)); }",
        ),
        (
            "callbacks/negative.js",
            "const {pass}=require('./helper.cjs'); const {promisify}=require('node:util'); const adapted=promisify(pass); function handle(req) { pass(req.query.command,(err,value)=>eval(value)); adapted(req.query.command).then(value=>eval(value)); }",
        ),
        (
            "slots/select.ts",
            "export function select(a,b) { return a; }",
        ),
        (
            "slots/select.cjs",
            "function select(a,b){return b;} module.exports={select};",
        ),
        (
            "slots/positive.ts",
            "import cp from 'node:child_process'; import {select} from './select.js'; export function handle(req:any){cp.exec(select(req.query.command,'safe'));}",
        ),
        (
            "slots/positive.js",
            "const cp=require('node:child_process'); const {select}=require('./select.cjs'); function handle(req){cp.exec(select('safe',req.query.command));}",
        ),
        (
            "slots/negative.ts",
            "import cp from 'node:child_process'; import {select} from './select.js'; export function handle(req:any){cp.exec(select('safe',req.query.command));}",
        ),
        (
            "slots/negative.js",
            "const cp=require('node:child_process'); const {select}=require('./select.cjs'); function handle(req){cp.exec(select(req.query.command,'safe'));}",
        ),
        (
            "mongo/helper.ts",
            "const db={}; export function find(cb){ db.collection('notes').find().toArray(cb); }",
        ),
        (
            "mongo/helper.cjs",
            "function find(cb){cb(null,'safe');} module.exports={find};",
        ),
        (
            "mongo/positive.ts",
            "import {find} from './helper.js'; export function handle(req:any,res:any){find((err,value)=>res.send(value));}",
        ),
        (
            "mongo/negative.js",
            "const {find}=require('./helper.cjs'); function handle(req,res){find((err,value)=>res.send(value));}",
        ),
        (
            "xml/helper.ts",
            "xmlRegisterFsInputProviders(); export function parse(value){return vm.runInContext(XmlDocument.fromString(value,XML_PARSE_NOENT|XML_PARSE_DTDLOAD));}",
        ),
        (
            "xml/helper.cjs",
            "function parse(value){return 'safe';} module.exports={parse};",
        ),
        (
            "xml/positive.ts",
            "import {parse} from './helper.js'; export function handle(req:any){parse(req.body.xml);}",
        ),
        (
            "xml/negative.js",
            "const {parse}=require('./helper.cjs'); function handle(req){parse(req.body.xml);}",
        ),
        (
            "adapter/api.mjs",
            "import {callbackify as wrap,promisify as promise} from 'node:util'; async function echo(v){return v;} function forward(v,cb){cb(null,v);} export default {echo:wrap(echo),forward:promise(forward)};",
        ),
        (
            "adapter/api.cjs",
            "const {callbackify:wrap,promisify:promise}=require('node:util'); async function echo(v){return 'safe';} function forward(v,cb){cb(null,'safe');} module.exports={echo:wrap(echo),forward:promise(forward)};",
        ),
        (
            "adapter/positive.ts",
            "import api from './api.mjs'; export function handle(req:any){api.echo(req.query.command,(err,value)=>eval(value));api.forward(req.query.command).then(value=>eval(value));}",
        ),
        (
            "adapter/negative.js",
            "const api=require('./api.cjs'); function handle(req){api.echo(req.query.command,(err,value)=>eval(value));api.forward(req.query.command).then(value=>eval(value));}",
        ),
    ] {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (file, capability) in [
        ("returns/positive.ts", Capability::ProcessExecution),
        ("callbacks/positive.ts", Capability::DynamicCodeExecution),
        ("adapter/positive.ts", Capability::DynamicCodeExecution),
        ("slots/positive.ts", Capability::ProcessExecution),
        ("slots/positive.js", Capability::ProcessExecution),
        ("mongo/positive.ts", Capability::HtmlOutput),
        ("xml/positive.ts", Capability::XmlParsing),
    ] {
        assert!(
            scan.security_paths
                .iter()
                .any(|p| p.capability == capability
                    && p.steps.last().is_some_and(|s| s.location.path == file)),
            "lost exact-owner flow in {file}"
        );
    }
    assert!(
        scan.security_paths.iter().all(|p| !p
            .steps
            .last()
            .unwrap()
            .location
            .path
            .contains("negative")),
        "clean sibling inherited a source/sink contract"
    );
    fs::remove_dir_all(root).unwrap();
}
