use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn documentation_and_client_callbacks_do_not_replace_actual_server_handlers() {
    let root =
        std::env::temp_dir().join(format!("mehscan-review-boundaries-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("Controller.ts"),
        r#"
import {Controller, Post, Delete} from '@nestjs/common';
@Controller('/items')
class ItemsController {
 @Post('/reserve')
 @ApiResponse({
   schema: {
      description: 'create reservation',
      properties: { result: {example:'delete'} }
   }
 })
 @ApiOperation({description:'update selected resource'})
 async reserveSlot(input:any) {
   return this.service.createReservation(input);
 }
 @Delete('/:id')
 @ApiResponse({description:'delete response'})
 async deleteItem(id:string) { return this.service.deleteItem(id); }
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("Client.tsx"),
        r#"
const updateMutation = client.update.useMutation({
 onSuccess: async (value) => { setProfile(value); },
});
const createMutation = client.create.useMutation({
 onSuccess: async () => { await saveLocalPreferences(); },
});
"#,
    )
    .unwrap();
    fs::write(
        root.join("Resolvers.ts"),
        r#"
export const resolvers = {
 Mutation: {
  updateProfile: async (parent,input,ctx) => {
    return ctx.service.updateProfile(input);
  }
 },
 Query: {
  view: async () => { return createView(); }
 }
};
const hooks = useMutation({
 onSuccess: async () => { updateUi(); }
});
"#,
    )
    .unwrap();
    fs::write(
        root.join("Routes.ts"),
        r#"
const clientMutation = {};
app.post('/items', async (req,res) => { await service.updateItem(req.body); });
"#,
    )
    .unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let markers = inventory
        .entries
        .iter()
        .filter(|r| r.rule_id == "framework-authorization-review-marker")
        .collect::<Vec<_>>();
    for name in ["reserveSlot", "deleteItem", "updateProfile"] {
        assert!(
            markers.iter().any(|r| r.symbol.as_deref() == Some(name)),
            "missing real handler {name}: {markers:?}"
        );
    }
    assert!(
        !markers.iter().any(|r| r.path == "Client.tsx"
            || r.symbol.as_deref() == Some("onSuccess")
            || r.symbol.as_deref() == Some("schema")),
        "spurious boundary: {markers:?}"
    );
    assert!(
        markers.iter().any(|r| r.path == "Routes.ts"),
        "HTTP route must survive nearby client Mutation text"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn budget_continuation_is_disjoint_complete_and_source_bound() {
    use mehscan_engine::investigation::*;
    use std::collections::BTreeSet;
    let root = std::env::temp_dir().join(format!("mehscan-marker-pages-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    for file in 0..7 {
        let mut source = "import {Controller, Post} from '@nestjs/common';\n@Controller('/items')\nclass ItemsController {\n".to_string();
        for method in 0..10 {
            source.push_str(&format!(" @Post('/{method}')\n async updateItem{method}(input:any) {{ return this.service.updateItem(input); }}\n"));
        }
        source.push_str("}\n");
        fs::write(root.join(format!("Controller{file}.ts")), source).unwrap();
    }
    fs::write(
        root.join("Ordinary.ts"),
        "function run(req:any) { eval(req.query.code); }\n",
    )
    .unwrap();
    let mut initial = build_review_inventory(&root, false).unwrap();
    assert!(
        initial
            .entries
            .iter()
            .any(|entry| entry.rule_id != "framework-authorization-review-marker")
    );
    bind_inventory_repository(&mut initial, Some("evaluation:marker-pages".into()), None).unwrap();
    let mut seen = BTreeSet::new();
    let mut previous = 0;
    for page in 0..4 {
        let inventory = if page == 0 {
            initial.clone()
        } else {
            continue_review_markers(&root, &initial, page).unwrap()
        };
        if page > 0 {
            assert!(
                inventory
                    .entries
                    .iter()
                    .all(|entry| entry.rule_id == "framework-authorization-review-marker")
            );
        }
        let coverage = &inventory.marker_admission;
        assert_eq!(coverage.recognized, 70);
        assert_eq!(coverage.previously_admitted, previous);
        assert_eq!(
            coverage.recognized,
            previous + coverage.admitted + coverage.budget_deferred
        );
        assert!(coverage.admitted <= 48);
        let markers = inventory
            .entries
            .iter()
            .filter(|r| r.rule_id == "framework-authorization-review-marker")
            .collect::<Vec<_>>();
        assert_eq!(markers.len(), coverage.admitted);
        for entry in &markers {
            assert!(seen.insert(entry.review_id.clone()), "repeated marker");
        }
        for file in 0..7 {
            assert!(
                markers
                    .iter()
                    .filter(|r| r.path == format!("Controller{file}.ts"))
                    .count()
                    <= 8
            );
        }
        if page == 1 {
            let ids = markers.iter().map(|r| r.review_id.clone()).collect();
            let job = build_selected_review_jobs(&root, &inventory, &ids, None).unwrap();
            assert_eq!(job.total_reviews, markers.len());
            let bundles = build_path_review_bundles(&job, None).unwrap();
            assert!(!bundles.bundles.is_empty());
            let validator = ReviewHistoryValidator::new(&root, &inventory).unwrap();
            for bundle in bundles.bundles {
                validator.validate_bundle(&bundle).unwrap();
            }
            let repeated = continue_review_markers(&root, &initial, page).unwrap();
            assert_eq!(
                repeated
                    .entries
                    .iter()
                    .map(|e| &e.review_id)
                    .collect::<Vec<_>>(),
                inventory
                    .entries
                    .iter()
                    .map(|e| &e.review_id)
                    .collect::<Vec<_>>()
            );
        }
        previous += coverage.admitted;
    }
    assert_eq!(seen.len(), 70);
    fs::write(root.join("Controller0.ts"), "// source changed").unwrap();
    assert!(continue_review_markers(&root, &initial, 1).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn http_markers_require_invocation_shape_not_database_or_documentation_text() {
    let root =
        std::env::temp_dir().join(format!("mehscan-route-invocations-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "Orm.ts",
            "async function main() { await prisma.app.delete({where: {slug: process.argv[2]}}); }",
            false,
        ),
        (
            "OrmPromise.ts",
            "const result = db.server.delete({where: {id}}).then(removeCache);",
            false,
        ),
        (
            "Object.ts",
            "const result = app.delete( /* options */ {where: {id}});",
            false,
        ),
        (
            "Documentation.ts",
            "const usage = `app.delete('/items', deleteItem)`;",
            false,
        ),
        (
            "ChainDocumentation.ts",
            "const usage = `router.route('/items').delete(deleteItem)`;",
            false,
        ),
        (
            "Broken.ts",
            "app.delete(routePath, deleteItem);\nfunction unfinished(",
            true,
        ),
        (
            "Structured.ts",
            "app.post({path: '/items', handler: createItem});",
            true,
        ),
        (
            "ShorthandStructured.ts",
            "server.delete({path: '/items', handler});",
            true,
        ),
        ("Dynamic.ts", "router.delete(routePath, deleteItem);", true),
        (
            "Multiline.ts",
            "router.patch(\n routePath,\n authenticate,\n updateItem\n);",
            true,
        ),
        (
            "Nested.ts",
            "this.router.delete(routePath, handlers.deleteItem);",
            true,
        ),
        (
            "SplitReceiver.ts",
            "this\n .router.delete(routePath, handlers.deleteItem);",
            true,
        ),
        (
            "Alias.ts",
            "itemsRouter.delete(routePath, deleteItem);",
            true,
        ),
        (
            "Fastify.ts",
            "fastify.patch(routePath, {preHandler: authorize}, async (req) => { return service.updateItem(req.body); });",
            true,
        ),
        (
            "Chained.ts",
            "router.route(routePath)\n .delete(authenticate, deleteItem);",
            true,
        ),
        ("Spread.ts", "app.delete(...deleteRoute);", true),
        (
            "Mixed.ts",
            "prisma.app.delete({where: {id}}); app.delete(routePath, deleteItem);",
            true,
        ),
    ];
    for (name, source, _) in &cases {
        fs::write(root.join(name), source).unwrap();
    }
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 1);
    for (name, _, expected) in &cases {
        let present = inventory
            .entries
            .iter()
            .any(|r| r.path == *name && r.rule_id == "framework-authorization-review-marker");
        assert_eq!(present, *expected, "unexpected marker admission for {name}");
    }
    fs::remove_dir_all(root).unwrap();
}
