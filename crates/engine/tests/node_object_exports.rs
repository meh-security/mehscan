use mehscan_core::Capability;
use std::fs;

#[test]
fn explicit_object_members_and_node_adapters_preserve_inputs_and_result_slots() {
    let root = std::env::temp_dir().join(format!("mehscan-object-exports-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for (file, source) in [
        (
            "api.mjs",
            r#"
import files from 'node:fs/promises';
import fs from 'node:fs';
import {callbackify as wrap, promisify as promise} from 'node:util';
async function read(path) { return files.readFile(path); }
async function echo(value) { return value; }
async function clean(value) { value='safe'; return value; }
function forward(value, callback) { callback(null, value); }
function remove(path, callback) { return fs.unlink(path, callback); }
export default {
  read: wrap(read), echo: wrap(echo), clean: wrap(clean),
  asPromise: promise(forward), remove: promise(remove),
  promises: {read, echo},
  inline(path) { return files.readFile(path); }
};
"#,
        ),
        ("barrel.mjs", "export {default as api} from './api.mjs';"),
        ("default-barrel.mjs", "export {default} from './api.mjs';"),
        (
            "common-alias.cjs",
            "const fs=require('node:fs'); function read(p){return fs.readFileSync(p);} const api={read}; module.exports=api;",
        ),
        (
            "common-replaced.cjs",
            "const fs=require('node:fs'); function read(p){return fs.readFileSync(p);} module.exports={read}; module.exports.read=other;",
        ),
        (
            "common.cjs",
            "const fs=require('node:fs'); const {promisify:promise}=require('node:util'); function read(p,cb){fs.readFile(p,cb);} module.exports={read:promise(read), nested:{read}};",
        ),
        (
            "spread.mjs",
            "import fs from 'node:fs'; function read(p){return fs.readFileSync(p);} export default {read, ...other};",
        ),
        (
            "duplicate.mjs",
            "import fs from 'node:fs'; function read(p){return fs.readFileSync(p);} export default {read, read:other};",
        ),
        (
            "computed.mjs",
            "import fs from 'node:fs'; function read(p){return fs.readFileSync(p);} export default {[key]:read};",
        ),
        (
            "replaced.mjs",
            "import fs from 'node:fs'; function read(p){return fs.readFileSync(p);} const api={read}; api.read=other; export default api;",
        ),
        (
            "lookalike.mjs",
            "import fs from 'node:fs'; import {callbackify} from 'unrelated'; async function read(p){return fs.readFileSync(p);} export default {read:callbackify(read)};",
        ),
        (
            "custom.mjs",
            "import fs from 'node:fs'; import {promisify} from 'node:util'; function read(p,cb){return fs.readFile(p,cb);} read[promisify.custom]=other; export default {read:promisify(read)};",
        ),
    ] {
        fs::write(root.join(file), source).unwrap();
    }
    let read = Capability::FilesystemRead;
    let write = Capability::FilesystemWrite;
    let code = Capability::DynamicCodeExecution;
    let cases = [
        (
            "commonAlias",
            "const api=require('./common-alias.cjs');",
            "api.read(req.query.path);",
            true,
            read,
        ),
        (
            "commonReplaced",
            "const api=require('./common-replaced.cjs');",
            "api.read(req.query.path);",
            false,
            read,
        ),
        (
            "nested",
            "import api from './api.mjs';",
            "api.promises.read(req.query.path);",
            true,
            read,
        ),
        (
            "callback",
            "import api from './api.mjs';",
            "api.read(req.query.path, ()=>{});",
            true,
            read,
        ),
        (
            "promisify",
            "import api from './api.mjs';",
            "api.remove(req.query.path);",
            true,
            write,
        ),
        (
            "inline",
            "import api from './api.mjs';",
            "api.inline(req.query.path);",
            true,
            read,
        ),
        (
            "barrel",
            "import {api} from './barrel.mjs';",
            "api.promises.read(req.query.path);",
            true,
            read,
        ),
        (
            "defaultBarrel",
            "import api from './default-barrel.mjs';",
            "api.promises.read(req.query.path);",
            true,
            read,
        ),
        (
            "namespace",
            "import * as ns from './api.mjs';",
            "ns.default.promises.read(req.query.path);",
            true,
            read,
        ),
        (
            "common",
            "import api from './common.cjs';",
            "api.read(req.query.path);",
            true,
            read,
        ),
        (
            "commonNested",
            "const api=require('./common.cjs');",
            "api.nested.read(req.query.path, ()=>{});",
            true,
            read,
        ),
        (
            "callbackValue",
            "import api from './api.mjs';",
            "api.echo(req.query.value, (err,value)=>eval(value));",
            true,
            code,
        ),
        (
            "promiseValue",
            "import api from './api.mjs';",
            "api.asPromise(req.query.value).then(value=>eval(value));",
            true,
            code,
        ),
        (
            "errorSlot",
            "import api from './api.mjs';",
            "api.echo(req.query.value, (err,value)=>eval(err));",
            false,
            code,
        ),
        (
            "callbackOverwrite",
            "import api from './api.mjs';",
            "api.clean(req.query.value, (err,value)=>eval(value));",
            false,
            code,
        ),
        (
            "directReturn",
            "import api from './api.mjs';",
            "eval(api.echo(req.query.value, ()=>{}));",
            false,
            code,
        ),
        (
            "promiseObject",
            "import api from './api.mjs';",
            "eval(api.promises.echo(req.query.value));",
            false,
            code,
        ),
        (
            "awaited",
            "import api from './api.mjs';",
            "eval(await api.promises.echo(req.query.value));",
            true,
            code,
        ),
        (
            "callbackSlot",
            "import api from './api.mjs';",
            "api.read('safe',req.query.path);",
            false,
            read,
        ),
        (
            "spread",
            "import api from './spread.mjs';",
            "api.read(req.query.path);",
            false,
            read,
        ),
        (
            "duplicate",
            "import api from './duplicate.mjs';",
            "api.read(req.query.path);",
            false,
            read,
        ),
        (
            "computed",
            "import api from './computed.mjs';",
            "api.read(req.query.path);",
            false,
            read,
        ),
        (
            "replaced",
            "import api from './replaced.mjs';",
            "api.read(req.query.path);",
            false,
            read,
        ),
        (
            "lookalike",
            "import api from './lookalike.mjs';",
            "api.read(req.query.path, ()=>{});",
            false,
            read,
        ),
        (
            "custom",
            "import api from './custom.mjs';",
            "api.read(req.query.path);",
            false,
            read,
        ),
        (
            "wrongNamespace",
            "import * as ns from './api.mjs';",
            "ns.promises.read(req.query.path);",
            false,
            read,
        ),
        (
            "callerShadow",
            "import api from './api.mjs';",
            "const api=other; api.promises.read(req.query.path);",
            false,
            read,
        ),
    ];
    for (index, (name, imports, body, _, _)) in cases.iter().enumerate() {
        let extension = ["js", "ts", "tsx"][index % 3];
        let annotation = if extension == "js" { "" } else { ":any" };
        fs::write(
            root.join(format!("{name}.{extension}")),
            format!("{imports}\nexport async function handle(req{annotation}) {{ {body} }}"),
        )
        .unwrap();
    }
    let scan = mehscan_engine::scan_path(&root).unwrap();
    for (index, (name, _, _, expected, capability)) in cases.iter().enumerate() {
        let path = format!("{name}.{}", ["js", "ts", "tsx"][index % 3]);
        let found = scan.security_paths.iter().any(|p| {
            p.capability == *capability && p.steps.last().is_some_and(|s| s.location.path == path)
        });
        assert_eq!(
            found,
            *expected,
            "wrong flow in {path}: {:#?}",
            scan.security_paths
                .iter()
                .filter(|p| p.steps.last().is_some_and(|s| s.location.path == path))
                .collect::<Vec<_>>()
        );
    }
    fs::remove_dir_all(root).unwrap();
}
