use mehscan_core::{Capability, EvidenceKind, OperandFactKind};
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn boolean_consumption_does_not_close_authorization_or_hide_escaping_records() {
    let cases = [
        (
            "guard",
            "const row=await Records.findOne({where:{id}}); if(row) throw new Error('taken'); return true;",
            true,
        ),
        (
            "negated",
            "return !(await Records.findOne({where:{id}}));",
            true,
        ),
        (
            "nullTest",
            "const row=await Records.findOne({where:{id}}); return row !== null;",
            true,
        ),
        (
            "reverseNull",
            "const row=await Records.findOne({where:{id}}); return null === row;",
            true,
        ),
        (
            "ternary",
            "const row=await store.query('records').findOne({where:{id}}); return row ? 409 : 200;",
            true,
        ),
        (
            "multipleTests",
            "const row=await Records.findOne({where:{id}}); if(!row) return false; return row !== null;",
            true,
        ),
        // This fact describes the local expression, not whether the promise
        // was awaited or an actual database-existence test took place.
        (
            "promiseTruthiness",
            "const row=Records.findOne({where:{id}}); return !row;",
            true,
        ),
        (
            "returnRecord",
            "const row=await Records.findOne({where:{id}}); return row;",
            false,
        ),
        (
            "readField",
            "const row=await Records.findOne({where:{id}}); return row.secret;",
            false,
        ),
        (
            "alias",
            "const row=await Records.findOne({where:{id}}); const other=row; return !other;",
            false,
        ),
        (
            "shorthand",
            "const row=await Records.findOne({where:{id}}); return {row};",
            false,
        ),
        (
            "passedToHelper",
            "const row=await Records.findOne({where:{id}}); return consume(row);",
            false,
        ),
        (
            "callback",
            "const row=await Records.findOne({where:{id}}); return () => !row;",
            false,
        ),
        (
            "shadow",
            "const row=await Records.findOne({where:{id}}); if(row) return false; { const row=null; if(row) return false; } return true;",
            false,
        ),
        (
            "mutable",
            "let row=await Records.findOne({where:{id}}); row=null; return !row;",
            false,
        ),
        (
            "fieldMutation",
            "const row=await Records.findOne({where:{id}}); row.owner=id; return !row;",
            false,
        ),
        (
            "fallback",
            "const row=await Records.findOne({where:{id}}); return row || {};",
            false,
        ),
        (
            "mixedUses",
            "const row=await Records.findOne({where:{id}}); if(!row) return false; return row.secret;",
            false,
        ),
        (
            "unused",
            "const row=await Records.findOne({where:{id}}); return true;",
            false,
        ),
        (
            "deleteEffect",
            "return !await Records.destroy({where:{id}});",
            false,
        ),
    ];
    for extension in ["js", "ts", "tsx"] {
        let root = std::env::temp_dir().join(format!(
            "mehscan-resource-result-{}-{extension}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let source = cases
            .iter()
            .map(|(name, body, _)| format!("async function {name}(id) {{ {body} }}\n"))
            .collect::<String>();
        fs::write(root.join(format!("app.{extension}")), source).unwrap();
        let inventory = build_review_inventory(&root, false).unwrap();
        assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
        for (symbol, _, expected) in cases {
            let sink = inventory
                .scan
                .evidence
                .iter()
                .find(|e| {
                    e.kind == EvidenceKind::Sink
                        && e.capability == Capability::ResourceAccess
                        && e.enclosing_symbol.as_deref() == Some(symbol)
                })
                .unwrap_or_else(|| panic!("missing {extension} lookup {symbol}"));
            let fact = sink.context.operand_facts.iter().find(|f| {
                f.kind == OperandFactKind::QueryStructure
                    && f.role == "resource_result"
                    && f.value == "result_use:boolean_or_null_test_only"
            });
            assert_eq!(fact.is_some(), expected, "{extension} {symbol}");
            if let Some(fact) = fact {
                assert!(fact.remaining_checks.contains(&"selector_authority".into()));
                assert!(
                    fact.remaining_checks
                        .contains(&"observable_existence_disclosure".into())
                );
                assert!(sink.context.resource_policy.is_none());
            }
            // Neither the observed boolean use nor its absence changes review
            // admission. Errors/status differences can still disclose secrets.
            assert!(
                inventory.entries.iter().any(|e| {
                    e.capability == Capability::ResourceAccess
                        && e.symbol.as_deref() == Some(symbol)
                        && e.value_hint.is_none()
                }),
                "{extension} {symbol} lost its unresolved review"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
