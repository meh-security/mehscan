use mehscan_core::{Capability, EvidenceKind, OperandFactKind};
use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn selector_origins_close_only_complete_fixed_filters_not_identity_or_escaping_inputs() {
    let cases = [
        (
            "fixedObject",
            "const filter={type:'default'}; return Records.findOne({where:filter});",
            true,
        ),
        (
            "fixedScalar",
            "const type='default'; return store.query('roles').findOne({where:{type}});",
            true,
        ),
        (
            "fixedFields",
            "const active=true; const filter={type:'default', active}; return Records.findOne({where:filter});",
            true,
        ),
        (
            "fixedWithOptions",
            "const populate=[]; const filter={type:'default'}; return Records.findOne({where:filter, populate});",
            true,
        ),
        (
            "requestInput",
            "const id=req.query.id; return Records.findOne({where:{id}});",
            false,
        ),
        (
            "identityContext",
            "const id=req.user.id; return Accounts.findOne({where:{id}});",
            false,
        ),
        // Matching a subject's ID to an unrelated resource key is not ownership.
        (
            "differentResource",
            "const id=req.user.id; return Invoices.findOne({where:{id}});",
            false,
        ),
        (
            "contextMember",
            "return Accounts.findOne({where:{id:ctx.state.user.id}});",
            false,
        ),
        ("parameter", "return Records.findOne({where:{id}});", false),
        (
            "mutableScalar",
            "let type='default'; return Records.findOne({where:{type}});",
            false,
        ),
        (
            "mutableObject",
            "let filter={type:'default'}; return Records.findOne({where:filter});",
            false,
        ),
        (
            "mutation",
            "const filter={id:'fixed'}; filter.id=req.query.id; return Records.findOne({where:filter});",
            false,
        ),
        (
            "escape",
            "const filter={id:'fixed'}; change(filter); return Records.findOne({where:filter});",
            false,
        ),
        (
            "aliasEscape",
            "const filter={id:'fixed'}; const alias=filter; alias.id=req.query.id; return Records.findOne({where:filter});",
            false,
        ),
        (
            "closure",
            "const filter={id:'fixed'}; const change=()=>{filter.id=req.query.id}; change(); return Records.findOne({where:filter});",
            false,
        ),
        (
            "lateArgument",
            "const filter={id:'fixed'}; return Records.findOne({where:filter, extra:change(filter)});",
            false,
        ),
        (
            "overriddenWhere",
            "const filter={id:'fixed'}; return Records.findOne({where:filter, ...req.query});",
            false,
        ),
        (
            "duplicateWhere",
            "const filter={id:'fixed'}; return Records.findOne({where:filter, where:req.query});",
            false,
        ),
        (
            "overriddenInlineWhere",
            "return Records.findOne({where:{id:'fixed'}, ...req.query});",
            false,
        ),
        (
            "duplicateInlineWhere",
            "return Records.findOne({where:{id:'fixed'}, where:req.query});",
            false,
        ),
        (
            "dynamicScope",
            "const filter={id:'fixed'}; eval('filter.id = req.query.id'); return Records.findOne({where:filter});",
            false,
        ),
        (
            "spread",
            "const filter={...req.query, type:'default'}; return Records.findOne({where:filter});",
            false,
        ),
        (
            "duplicate",
            "const filter={id:'fixed', id:req.query.id}; return Records.findOne({where:filter});",
            false,
        ),
        (
            "computed",
            "const filter={[id]:'default'}; return Records.findOne({where:filter});",
            false,
        ),
        (
            "nestedOperator",
            "const filter={id:{$ne:null}}; return Records.findOne({where:filter});",
            false,
        ),
        (
            "prototype",
            "const filter={__proto__:req.query, type:'default'}; return Records.findOne({where:filter});",
            false,
        ),
        (
            "tooWide",
            "const filter={a:1,b:2,c:3,d:4,e:5,f:6,g:7,h:8,i:9}; return Records.findOne({where:filter});",
            false,
        ),
    ];
    for extension in ["js", "ts", "tsx"] {
        let root = std::env::temp_dir().join(format!(
            "mehscan-resource-selector-{}-{extension}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        // Eval is deliberately in its own module: its presence conservatively
        // vetoes alias closure throughout that module, not unrelated files.
        for (name, body, _) in cases {
            let parameters = if matches!(
                name,
                "requestInput" | "identityContext" | "differentResource"
            ) {
                "req, ctx"
            } else {
                "req, ctx, id"
            };
            fs::write(
                root.join(format!("{name}.{extension}")),
                format!("async function {name}({parameters}) {{ {body} }}"),
            )
            .unwrap();
        }
        let inventory = build_review_inventory(&root, false).unwrap();
        assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
        for (symbol, _, fixed) in cases {
            let sink = inventory
                .scan
                .evidence
                .iter()
                .find(|e| {
                    e.kind == EvidenceKind::Sink
                        && e.capability == Capability::ResourceAccess
                        && e.enclosing_symbol.as_deref() == Some(symbol)
                })
                .unwrap_or_else(|| panic!("missing {extension} {symbol}"));
            let closed = sink.context.operand_facts.iter().any(|f| {
                f.kind == OperandFactKind::QueryStructure
                    && f.role == "filter"
                    && f.value == "resource_selector:fixed_equality"
            });
            assert_eq!(closed, fixed, "{extension} {symbol} selector closure");
            assert_eq!(
                inventory.entries.iter().any(|e| {
                    e.capability == Capability::ResourceAccess
                        && e.symbol.as_deref() == Some(symbol)
                }),
                !fixed,
                "{extension} {symbol} review admission"
            );
            if matches!(
                symbol,
                "requestInput" | "identityContext" | "differentResource"
            ) {
                let origin = sink
                    .context
                    .operand_facts
                    .iter()
                    .find(|f| {
                        f.kind == OperandFactKind::QueryStructure
                            && f.role == "resource_selector.id"
                            && f.value == "selector_origin:member_read"
                    })
                    .unwrap_or_else(|| panic!("missing member producer for {symbol}"));
                assert!(
                    origin
                        .remaining_checks
                        .contains(&"resource_identity_matches_subject".into())
                );
                assert!(sink.context.resource_policy.is_none());
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
}
