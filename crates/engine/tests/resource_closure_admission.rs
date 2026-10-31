use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::build_review_inventory;

#[test]
fn resource_closures_require_complete_literals_not_create_coincidence_or_outer_quotes() {
    let root =
        std::env::temp_dir().join(format!("mehscan-resource-closures-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let variants = [
        (
            "mutated",
            "const created=await Rows.create(req.body); created.id=req.query.id; return read(created.id);",
        ),
        (
            "shadowed",
            "const created=await Rows.create(req.body); return read(created.id);",
        ),
        (
            "reordered",
            "const result=await read(created.id); const created=await Rows.create(req.body); return result;",
        ),
    ];
    for extension in ["js", "ts", "tsx"] {
        for (name, body) in variants {
            let parameters = if name == "shadowed" {
                "req,Rows"
            } else {
                "req"
            };
            std::fs::write(root.join(format!("{name}.{extension}")), format!("function read(id) {{ return Rows.findOne({{where:{{id:id}}}}); }}\nasync function run({parameters}) {{ {body} }}")).unwrap();
        }
        std::fs::write(root.join(format!("strings.{extension}")), "function dynamic(key) { return Rows.findOne({where:{id:'pre' + key + 'post'}}); }\nfunction keyword(None) { return Rows.findOne({where:{id:None}}); }\nfunction fixed() { return Rows.findOne({where:{id:'prepost'}}); }\nfunction escapedFixed() { return Rows.findOne({where:{id:'can\\\'t'}}); }").unwrap();
    }
    std::fs::write(root.join("strings.py"), "from django.db import models\nclass Row(models.Model):\n    pass\ndef dynamic(key):\n    return Row.objects.get(pk='pre' + key + 'post')\ndef keyword(null):\n    return Row.objects.get(pk=null)\ndef fixed():\n    return Row.objects.get(pk='prepost')\n").unwrap();
    std::fs::write(root.join("Strings.cs"), "using Microsoft.EntityFrameworkCore; class Row { public string Id {get;set;} } class AppDb:DbContext { public DbSet<Row> Rows {get;set;} } class App { object Dynamic(AppDb db,string key) { return db.Rows.FirstOrDefault(x=>x.Id==\"pre\"+key+\"post\"); } object Fixed(AppDb db) { return db.Rows.FirstOrDefault(x=>x.Id==\"prepost\"); } }").unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    for extension in ["js", "ts", "tsx"] {
        for (name, _) in variants {
            let path = format!("{name}.{extension}");
            assert!(
                inventory
                    .entries
                    .iter()
                    .any(|e| e.path == path && e.capability == Capability::ResourceAccess),
                "unsound create proof hid {path}"
            );
        }
    }
    for (path, dynamic, fixed) in [
        ("strings.js", "dynamic", "fixed"),
        ("strings.ts", "dynamic", "fixed"),
        ("strings.tsx", "dynamic", "fixed"),
        ("strings.py", "dynamic", "fixed"),
        ("Strings.cs", "Dynamic", "Fixed"),
    ] {
        assert!(
            inventory.entries.iter().any(|e| e.path == path
                && e.symbol.as_deref() == Some(dynamic)
                && e.capability == Capability::ResourceAccess),
            "dynamic selector hidden in {path}"
        );
        assert!(
            !inventory.entries.iter().any(|e| e.path == path
                && [Some(fixed), Some("escapedFixed")].contains(&e.symbol.as_deref())
                && e.capability == Capability::ResourceAccess),
            "literal selector regressed in {path}"
        );
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.location.path == path
                    && e.enclosing_symbol.as_deref() == Some(fixed)
                    && e.kind == EvidenceKind::Sink
                    && e.capability == Capability::ResourceAccess),
            "closed selector must remain raw evidence in {path}"
        );
    }
    for path in ["strings.js", "strings.ts", "strings.tsx", "strings.py"] {
        assert!(
            inventory.entries.iter().any(|e| e.path == path
                && e.symbol.as_deref() == Some("keyword")
                && e.capability == Capability::ResourceAccess),
            "language-specific identifier mistaken for a literal in {path}"
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
