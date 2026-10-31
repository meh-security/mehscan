use mehscan_core::Capability;
use std::fs;

#[test]
fn object_fields_keep_separate_origins_and_stop_at_mutation_boundaries() {
    let root =
        std::env::temp_dir().join(format!("mehscan-field-projection-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "destructure",
            "const dto={bad:req.query.command,clean:'date'}; const {bad:command}=dto; cp.exec(command);",
            true,
        ),
        (
            "destructureClean",
            "const dto={bad:req.query.command,clean:'date'}; const {clean:command}=dto; cp.exec(command);",
            false,
        ),
        (
            "destructureNested",
            "const dto={nested:{bad:req.query.command}}; const {nested:{bad:command}}=dto; cp.exec(command);",
            true,
        ),
        (
            "destructureLiteral",
            "const {bad:command}={bad:req.query.command,clean:'date'}; cp.exec(command);",
            true,
        ),
        (
            "destructureDefault",
            "const dto={bad:req.query.command}; const {bad:command='date'}=dto; cp.exec(command);",
            false,
        ),
        (
            "destructureOverwrite",
            "const dto={bad:req.query.command}; let {bad:command}=dto; command='date'; cp.exec(command);",
            false,
        ),
        (
            "destructureAliasWrite",
            "const dto={nested:{bad:req.query.command}}; const {nested}=dto; nested.bad='date'; cp.exec(dto.nested.bad);",
            false,
        ),
        (
            "selected",
            "const dto={bad:req.query.command,clean:'date'}; cp.exec(dto.bad);",
            true,
        ),
        (
            "sibling",
            "const dto={bad:req.query.command,clean:'date'}; cp.exec(dto.clean);",
            false,
        ),
        (
            "alias",
            "const dto={bad:req.query.command,clean:'date'}; const command=dto.bad; cp.exec(command);",
            true,
        ),
        (
            "cleanAlias",
            "const dto={bad:req.query.command,clean:'date'}; const command=dto.clean; cp.exec(command);",
            false,
        ),
        (
            "nested",
            "const dto={nested:{bad:req.query.command,clean:'date'}}; cp.exec(dto.nested.bad);",
            true,
        ),
        (
            "nestedClean",
            "const dto={nested:{bad:req.query.command,clean:'date'}}; cp.exec(dto.nested.clean);",
            false,
        ),
        (
            "bracket",
            "const dto={bad:req.query.command,clean:'date'}; cp.exec(dto['bad']);",
            true,
        ),
        (
            "dynamic",
            "const dto={bad:req.query.command,clean:'date'}; cp.exec(dto[key]);",
            false,
        ),
        (
            "overwrite",
            "const dto={bad:req.query.command,clean:'date'}; dto.bad='date'; cp.exec(dto.bad);",
            false,
        ),
        (
            "branchWrite",
            "const dto={bad:req.query.command}; if(enabled) dto.bad='date'; cp.exec(dto.bad);",
            false,
        ),
        (
            "escape",
            "const dto={bad:req.query.command}; mutate(dto); cp.exec(dto.bad);",
            false,
        ),
        (
            "otherObject",
            "const dto={bad:req.query.command}; const other={bad:'date'}; cp.exec(other.bad);",
            false,
        ),
        (
            "spread",
            "const dto={bad:req.query.command,...other}; cp.exec(dto.bad);",
            false,
        ),
        (
            "duplicate",
            "const dto={bad:req.query.command,bad:'date'}; cp.exec(dto.bad);",
            false,
        ),
        (
            "guarded",
            "const dto={bad:req.query.command}; if(enabled) cp.exec(dto.bad);",
            true,
        ),
        (
            "scalarCopy",
            "const dto={bad:req.query.command}; const command=dto.bad; dto.bad='date'; cp.exec(command);",
            true,
        ),
        (
            "nestedMutation",
            "function mutate(){dto.bad='date';} const dto={bad:req.query.command}; mutate(); cp.exec(dto.bad);",
            false,
        ),
        (
            "laterClosure",
            "const dto={bad:req.query.command}; mutate(); cp.exec(dto.bad); function mutate(){unknown(dto);}",
            false,
        ),
        (
            "objectAlias",
            "const dto={bad:req.query.command}; const alias=dto; alias.bad='date'; cp.exec(dto.bad);",
            false,
        ),
        (
            "methodMutation",
            "const dto={bad:req.query.command, mutate:function(){this.bad='date';}}; dto.mutate(); cp.exec(dto.bad);",
            false,
        ),
        (
            "blockShadow",
            "const dto={bad:'date'}; {const dto={bad:req.query.command};} cp.exec(dto.bad);",
            false,
        ),
        (
            "scalarShadow",
            "const dto={bad:req.query.command}; const command='date'; {const command=dto.bad;} cp.exec(command);",
            false,
        ),
        (
            "scalarClosureWrite",
            "const dto={bad:req.query.command}; let command=dto.bad; function mutate(){command='date';} mutate(); cp.exec(command);",
            false,
        ),
    ];
    for (name, body, _) in cases {
        for ext in ["js", "ts", "tsx"] {
            fs::write(
                root.join(format!("{name}.{ext}")),
                format!("import cp from 'node:child_process'; function run(req,res){{{body}}}"),
            )
            .unwrap();
        }
    }
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
            assert_eq!(!paths.is_empty(), expected, "wrong field flow for {file}");
            if expected {
                assert!(
                    paths.iter().all(|p| p.steps.iter().any(|s| s
                        .symbol
                        .as_ref()
                        .is_some_and(|s| s.starts_with("field projection:")))),
                    "missing field proof {file}"
                );
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
