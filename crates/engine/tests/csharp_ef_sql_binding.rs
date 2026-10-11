use mehscan_core::{Capability, EvidenceKind};
use mehscan_engine::investigation::{ReviewInventory, build_review_inventory};

fn inventory(label: &str, files: &[(&str, &str)]) -> ReviewInventory {
    let root =
        std::env::temp_dir().join(format!("mehscan-ef-binding-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    for (path, source) in files {
        std::fs::write(root.join(path), source).unwrap();
    }
    let result = build_review_inventory(&root, false).unwrap();
    std::fs::remove_dir_all(root).unwrap();
    assert_eq!(result.scan.coverage.totals.parse_failed, 0);
    result
}

fn sql_symbols(result: &ReviewInventory) -> Vec<&str> {
    let mut symbols = result
        .scan
        .evidence
        .iter()
        .filter(|e| e.kind == EvidenceKind::Sink && e.capability == Capability::DatabaseQuery)
        .map(|e| e.enclosing_symbol.as_deref().unwrap())
        .collect::<Vec<_>>();
    symbols.sort();
    symbols
}

#[test]
fn modern_compiler_interpolation_leaves_both_queues_but_raw_and_strings_stay() {
    let result = inventory(
        "modern",
        &[(
            "App.cs",
            r#"
using System;
using Microsoft.EntityFrameworkCore;
class Row { }
class AppDb : DbContext { public DbSet<Row> Rows { get; set; } }
class App {
    object Bound(AppDb db, string input) {
        return db.Database.SqlQuery<int>($"SELECT id FROM rows WHERE name = {input}");
    }
    object Named(AppDb db, string input) {
        return db.Database.SqlQuery<int>(sql: $"SELECT id FROM rows WHERE name = {input}");
    }
    object Local(AppDb db, string input) {
        FormattableString sql = $"SELECT id FROM rows WHERE name = {input}";
        return db.Database.SqlQuery<int>(sql);
    }
    object SetLocal(AppDb db, string input) {
        System.FormattableString sql = $"SELECT * FROM rows WHERE name = {input}";
        return db.Rows.FromSql(sql);
    }
    object SetDirect(AppDb db, string input) {
        return db.Rows.FromSql(sql: $"SELECT * FROM rows WHERE name = {input}");
    }
    object SetParameter(DbSet<Row> rows, string input) {
        FormattableString sql = $"SELECT * FROM rows WHERE name = {input}";
        return rows.FromSql(sql);
    }
    object Raw(AppDb db, string input) {
        return db.Database.SqlQueryRaw<int>($"SELECT id FROM rows WHERE name = '{input}'");
    }
    object StringLocal(AppDb db, string input) {
        var sql = $"SELECT id FROM rows WHERE name = '{input}'";
        return db.Database.SqlQuery<int>(sql);
    }
    object SetString(AppDb db, string input) {
        var sql = $"SELECT * FROM rows WHERE name = '{input}'";
        return db.Rows.FromSql(sql);
    }
    object FromRaw(AppDb db, string input) {
        return db.Rows.FromSqlRaw($"SELECT * FROM rows WHERE name = '{input}'");
    }
}
"#,
        )],
    );
    assert_eq!(
        sql_symbols(&result),
        ["FromRaw", "Raw", "SetString", "StringLocal"]
    );
    for symbol in [
        "Bound",
        "Named",
        "Local",
        "SetLocal",
        "SetDirect",
        "SetParameter",
    ] {
        assert!(
            !result
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "{symbol}: {:?}",
            result.entries
        );
    }
    for symbol in ["Raw", "StringLocal", "SetString", "FromRaw"] {
        assert!(
            result
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "lost {symbol}: {:?}",
            result.entries
        );
    }
}

#[test]
fn legacy_and_unowned_contexts_do_not_inherit_modern_binding() {
    for (label, usings, base) in [
        ("legacy", "using System.Data.Entity;", "DbContext"),
        (
            "qualified-legacy",
            "using Microsoft.EntityFrameworkCore;",
            "System.Data.Entity.DbContext",
        ),
        ("unknown", "", "DbContext"),
        (
            "mixed",
            "using Microsoft.EntityFrameworkCore; using System.Data.Entity;",
            "DbContext",
        ),
    ] {
        let source = format!(
            r#"{usings}
class Row {{ }}
class AppDb : {base} {{ public DbSet<Row> Rows {{ get; set; }} }}
class App {{
    object Query(AppDb db, string input) {{ return db.Database.SqlQuery<int>($"SELECT id FROM rows WHERE name = '{{input}}'"); }}
    object Command(AppDb db, string input) {{ return db.Database.ExecuteSqlCommand($"DELETE FROM rows WHERE name = '{{input}}'"); }}
    object Raw(AppDb db, string input) {{ return db.Database.SqlQueryRaw<int>($"SELECT id FROM rows WHERE name = '{{input}}'"); }}
}}"#
        );
        let result = inventory(label, &[("App.cs", &source)]);
        assert_eq!(sql_symbols(&result), ["Command", "Query", "Raw"], "{label}");
        assert!(
            result
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some("Query")),
            "{label}: {:?}",
            result.entries
        );
    }
}

#[test]
fn arbitrary_formattable_producers_and_rebinding_remain_questions() {
    let result = inventory(
        "producers",
        &[(
            "App.cs",
            r#"
using System;
using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
class AppDb : DbContext { }
class App {
    object Factory(AppDb db, string input) {
        FormattableString sql = FormattableStringFactory.Create(input, new object[] { 1 });
        return db.Database.SqlQuery<int>(sql);
    }
    object Rebound(AppDb db, string input) {
        FormattableString sql = $"SELECT id FROM rows WHERE name = {input}";
        sql = FormattableStringFactory.Create(input, new object[] {});
        return db.Database.SqlQuery<int>(sql);
    }
    object Ref(AppDb db, string input) {
        FormattableString sql = $"SELECT id FROM rows WHERE name = {input}";
        Replace(ref sql);
        return db.Database.SqlQuery<int>(sql);
    }
    object Closure(AppDb db, string input) {
        FormattableString sql = $"SELECT id FROM rows WHERE name = {input}";
        Action change = () => { sql = FormattableStringFactory.Create(input, new object[] {}); };
        change();
        return db.Database.SqlQuery<int>(sql);
    }
    object Helper(AppDb db, string input) { return db.Database.SqlQuery<int>(Build(input)); }
    object Parameter(AppDb db, FormattableString sql) { return db.Database.SqlQuery<int>(sql); }
}
"#,
        )],
    );
    assert_eq!(
        sql_symbols(&result),
        [
            "Closure",
            "Factory",
            "Helper",
            "Parameter",
            "Rebound",
            "Ref"
        ]
    );
    for symbol in [
        "Closure",
        "Factory",
        "Helper",
        "Parameter",
        "Rebound",
        "Ref",
    ] {
        assert!(
            result
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some(symbol)),
            "lost {symbol}: {:?}",
            result.entries
        );
    }
}

#[test]
fn context_identity_crosses_files_and_accepts_global_imports_without_dbsets() {
    let result = inventory(
        "project",
        &[
            (
                "Imports.cs",
                "global using Microsoft.EntityFrameworkCore; global using System;",
            ),
            (
                "Db.cs",
                "namespace Storage; public class AppDb : DbContext { }",
            ),
            (
                "App.cs",
                r#"class App {
            object Bound(Storage.AppDb db, string input) {
                FormattableString sql = $"SELECT id FROM rows WHERE name = {input}";
                return db.Database.SqlQuery<int>(sql);
            }
            object Raw(Storage.AppDb db, string input) { return db.Database.SqlQueryRaw<int>($"SELECT id FROM rows WHERE name = '{input}'"); }
        }"#,
            ),
        ],
    );
    assert_eq!(sql_symbols(&result), ["Raw"]);
    assert!(
        !result
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("Bound"))
    );
    assert!(
        result
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("Raw"))
    );
}

#[test]
fn custom_facades_types_extensions_and_conflicting_contexts_veto_exclusions() {
    let call = r#"using Microsoft.EntityFrameworkCore; class App { object Query(AppDb db, string input) { return db.Database.SqlQuery<int>($"SELECT id FROM rows WHERE name = '{input}'"); } }"#;
    for (label, declaration, extra) in [
        (
            "facade",
            "using Microsoft.EntityFrameworkCore; class AppDb : DbContext { public new CustomFacade Database { get; set; } }",
            "",
        ),
        (
            "shadow",
            "using Microsoft.EntityFrameworkCore; class DbContext { } class AppDb : DbContext { }",
            "",
        ),
        (
            "extension",
            "using Microsoft.EntityFrameworkCore; class AppDb : DbContext { }",
            "static class Extensions { public static object SqlQuery<T>(this object facade, string sql) { return sql; } }",
        ),
        (
            "conflict",
            "using Microsoft.EntityFrameworkCore; namespace One { class AppDb : DbContext { } }",
            "namespace Two { class AppDb : System.Data.Entity.DbContext { } }",
        ),
        (
            "alias",
            "using Microsoft.EntityFrameworkCore; using DbContext = CustomContext; class AppDb : DbContext { }",
            "",
        ),
        (
            "global-alias",
            "using Microsoft.EntityFrameworkCore; class AppDb : DbContext { }",
            "global using DbContext = CustomContext;",
        ),
        (
            "non-ef-conflict",
            "using Microsoft.EntityFrameworkCore; namespace One { class AppDb : DbContext { } }",
            "namespace Two { class AppDb { public CustomFacade Database { get; set; } } }",
        ),
    ] {
        let result = inventory(
            label,
            &[
                ("Db.cs", declaration),
                ("App.cs", call),
                ("Extra.cs", extra),
            ],
        );
        assert_eq!(sql_symbols(&result), ["Query"], "{label}");
        assert!(
            result
                .entries
                .iter()
                .any(|e| e.symbol.as_deref() == Some("Query")),
            "{label}: {:?}",
            result.entries
        );
    }
}

#[test]
fn custom_set_types_do_not_inherit_formattable_binding() {
    let result = inventory(
        "custom-set",
        &[(
            "App.cs",
            r#"
using Microsoft.EntityFrameworkCore;
class Row { }
class AppDb : DbContext { public CustomDbSet<Row> Rows { get; set; } }
class App { object Query(AppDb db, string input) { return db.Rows.FromSql($"SELECT * FROM rows WHERE name = '{input}'"); } }
"#,
        )],
    );
    assert_eq!(sql_symbols(&result), ["Query"]);
    assert!(
        result
            .entries
            .iter()
            .any(|e| e.symbol.as_deref() == Some("Query"))
    );
}
