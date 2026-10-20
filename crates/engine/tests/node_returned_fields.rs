use mehscan_core::Capability;
use std::fs;

#[test]
fn returned_fields_use_exact_helpers_and_keep_input_fields_separate() {
    let root = std::env::temp_dir().join(format!("mehscan-returned-fields-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("helpers.js"),
        r#"
import files from 'node:fs/promises';
export function consume(input){files.readFile(input);return {clean:'date'};}
export function wrap(input) { return {command:input,clean:'date'}; }
export function nested(input) { return {nested:{command:input},clean:'date'}; }
export function select(input) { return {command:input.bad,clean:input.clean}; }
export function second(a,b) { return {command:b}; }
export function constant(input) { return {command:'date'}; }
export function opaque(input) { return {command:transform(input)}; }
export function mutated(input) { input.bad='date'; return {command:input.bad}; }
export function effect(input) { mutate(input); return {command:input.bad}; }
export function shorthand(input) { return {input}; }
export const arrow = (input) => ({command:input});
"#,
    )
    .unwrap();
    fs::write(
        root.join("helpers.cjs"),
        "function wrap(input){return {command:input,clean:'date'};} module.exports={wrap};",
    )
    .unwrap();
    fs::write(
        root.join("pair.js"),
        "export function wrap(input){return {command:input};}",
    )
    .unwrap();
    fs::write(
        root.join("pair.ts"),
        "export function wrap(input:string){return {command:'date'};}",
    )
    .unwrap();
    let cases = [
        (
            "exactJsTarget",
            "const dto=jsWrap(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "exactTsTarget",
            "const dto=tsWrap(req.query.command); cp.exec(dto.command);",
            false,
        ),
        (
            "commonjs",
            "const dto=commonWrap(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "commonjsShadow",
            "function commonWrap(input){return {command:'date'};} const dto=commonWrap(req.query.command); cp.exec(dto.command);",
            false,
        ),
        (
            "local",
            "const dto=localHelper(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "renamed",
            "const dto=renamedWrap(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "namespace",
            "const dto=helpers.wrap(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "selected",
            "const dto=wrap(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "clean",
            "const dto=wrap(req.query.command); cp.exec(dto.clean);",
            false,
        ),
        (
            "destructure",
            "const {command}=wrap(req.query.command); cp.exec(command);",
            true,
        ),
        (
            "nested",
            "const dto=nested(req.query.command); cp.exec(dto.nested.command);",
            true,
        ),
        (
            "nestedDestructure",
            "const {nested:{command}}=nested(req.query.command); cp.exec(command);",
            true,
        ),
        ("inline", "cp.exec(wrap(req.query.command).command);", true),
        (
            "inlineClean",
            "cp.exec(wrap(req.query.command).clean);",
            false,
        ),
        (
            "inputField",
            "const dto=select({bad:req.query.command,clean:'date'}); cp.exec(dto.command);",
            true,
        ),
        (
            "inputSibling",
            "const dto=select({bad:req.query.command,clean:'date'}); cp.exec(dto.clean);",
            false,
        ),
        (
            "position",
            "const dto=second('date',req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "otherPosition",
            "const dto=second(req.query.command,'date'); cp.exec(dto.command);",
            false,
        ),
        (
            "constant",
            "const dto=constant(req.query.command); cp.exec(dto.command);",
            false,
        ),
        (
            "opaque",
            "const dto=opaque(req.query.command); cp.exec(dto.command);",
            false,
        ),
        (
            "overwrite",
            "const dto=wrap(req.query.command); dto.command='date'; cp.exec(dto.command);",
            false,
        ),
        (
            "functionShadow",
            "function wrap(input){return {command: 'date'};} const dto=wrap(req.query.command); cp.exec(dto.command);",
            false,
        ),
        (
            "shadow",
            "function local(wrap){const dto=wrap(req.query.command);cp.exec(dto.command);}",
            false,
        ),
        (
            "shorthand",
            "const dto=shorthand(req.query.command); cp.exec(dto.input);",
            true,
        ),
        (
            "arrow",
            "const dto=arrow(req.query.command); cp.exec(dto.command);",
            true,
        ),
        (
            "mutated",
            "const dto=mutated({bad:req.query.command}); cp.exec(dto.command);",
            false,
        ),
        (
            "effect",
            "const dto=effect({bad:req.query.command}); cp.exec(dto.command);",
            false,
        ),
        (
            "spreadArguments",
            "const dto=second(...other,req.query.command); cp.exec(dto.command);",
            false,
        ),
    ];
    for (name, body, _) in cases {
        for ext in ["js", "ts", "tsx"] {
            fs::write(root.join(format!("{name}.{ext}")), format!("import cp from 'node:child_process'; import {{wrap as jsWrap}} from './pair.js'; import {{wrap as tsWrap}} from './pair.ts'; import {{wrap as renamedWrap}} from './helpers.js'; import * as helpers from './helpers.js'; const {{wrap:commonWrap}}=require('./helpers.cjs'); export function localHelper(input){{return {{command:input}};}} import {{wrap,nested,select,second,constant,opaque,shorthand,arrow,mutated,effect}} from './helpers.js'; function run(req,res){{{body}}}")).unwrap();
        }
    }
    fs::write(
        root.join("input-effect.js"),
        "import {consume} from './helpers.js'; function run(req){consume(req.query.command);}",
    )
    .unwrap();
    let scan = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    for (name, _, expected) in cases {
        for ext in ["js", "ts", "tsx"] {
            let file = format!("{name}.{ext}");
            let sink = scan
                .evidence
                .iter()
                .find(|e| e.location.path == file && e.capability == Capability::ProcessExecution)
                .unwrap();
            let paths = scan
                .security_paths
                .iter()
                .filter(|p| p.sink_evidence_id == sink.id)
                .collect::<Vec<_>>();
            assert_eq!(
                !paths.is_empty(),
                expected,
                "wrong returned field flow {file}"
            );
            if expected {
                assert!(
                    paths
                        .iter()
                        .any(|p| p.steps.iter().any(|s| (s.location.path == "helpers.js"
                            || s.location.path == "helpers.cjs"
                            || s.location.path == "pair.js"
                            || s.location.path == file)
                            && s.symbol
                                .as_ref()
                                .is_some_and(|s| s.starts_with("returned field:")))),
                    "missing callee proof {file}"
                );
            }
        }
    }
    let effect_sink = scan
        .evidence
        .iter()
        .find(|e| {
            e.location.path == "input-effect.js" && e.capability == Capability::FilesystemRead
        })
        .unwrap();
    assert!(
        scan.security_paths
            .iter()
            .any(|p| p.sink_evidence_id == effect_sink.id
                && !p
                    .uncertainty_reasons
                    .iter()
                    .any(|r| r == "node_object_field_projection_is_syntactic")),
        "input sink effects must remain separate from returned fields"
    );
    fs::remove_dir_all(root).unwrap();
}
