use mehscan_core::{Capability, OperandFactKind};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-csharp-operands-{label}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Review.cs"), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn query_envelopes_keep_original_operands_and_stop_at_changed_or_ambiguous_origins() {
    let source = r#"using Dapper;
using System.Data.Common;
using System.Data;
class Review {
object Fixed(DbConnection db, string value) { var cmd = new CommandDefinition("SELECT @value", new {value}, commandType: CommandType.Text); return db.Query(cmd); }
object Composed(DbConnection db, string value) { var cmd = new CommandDefinition("SELECT " + value, new {value}); return db.Query(cmd); }
object Named(DbConnection db, string value) { var cmd = new Dapper.CommandDefinition(parameters: new {value}, commandType: CommandType.Text, commandText: "SELECT @value"); return db.Query(cmd); }
object Procedure(DbConnection db, string value) { var cmd = new CommandDefinition(value, commandType: CommandType.StoredProcedure); return db.Query(cmd); }
object Changed(DbConnection db, string value) { var cmd = new CommandDefinition("SELECT @value", new {value}); cmd = new CommandDefinition(value); return db.Query(cmd); }
object Escaped(DbConnection db, string value) { var cmd = new CommandDefinition("SELECT @value", new {value}); Adjust(ref cmd); return db.Query(cmd); }
object Aliased(DbConnection db, string value) { var original = new CommandDefinition(value); var cmd = original; return db.Query(cmd); }
object Factory(DbConnection db, string value) { var cmd = Build(value); return db.Query(cmd); }
object Captured(DbConnection db, string value) { var cmd = new CommandDefinition("SELECT @value", new {value}); Change(); return db.Query(cmd); void Change() { cmd = new CommandDefinition(value); } }
object Nested(DbConnection db, string value) { var cmd = new CommandDefinition("SELECT @value", new {value}); return Run(() => db.Query(cmd)); }
}
"#;
    let fixture = Fixture::new("envelopes", source);
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, true).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let sink = |name: &str| {
        inventory
            .scan
            .evidence
            .iter()
            .find(|e| {
                e.enclosing_symbol.as_deref() == Some(name)
                    && e.rule_id == "csharp-dapper-database-query"
            })
            .unwrap()
    };
    for name in ["Fixed", "Composed", "Named", "Procedure"] {
        let item = sink(name);
        assert_eq!(item.captures["query"].text, "cmd");
        assert!(
            item.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::LocalOperandOrigin)
        );
        assert!(
            item.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::QueryStructure)
        );
        for role in ["query_text", "query_origin"] {
            let c = &item.captures[role];
            assert_eq!(
                &source[c.location.start.byte_offset..c.location.end.byte_offset],
                c.text
            );
        }
    }
    assert_eq!(
        sink("Named").captures["query_text"].text,
        "\"SELECT @value\""
    );
    assert_eq!(sink("Named").captures["query_values"].text, "new {value}");
    assert_eq!(
        sink("Procedure").captures["query_command_type"].text,
        "CommandType.StoredProcedure"
    );
    assert!(
        sink("Composed")
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::QueryStructure && f.value == "nonliteral_text")
    );
    for name in ["Changed", "Escaped", "Aliased", "Factory", "Captured"] {
        let item = sink(name);
        assert!(
            item.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary),
            "{name}: {item:?}"
        );
        assert!(!item.captures.contains_key("query_text"), "Reused {name}");
    }
    for name in [
        "Fixed",
        "Composed",
        "Named",
        "Procedure",
        "Changed",
        "Escaped",
        "Aliased",
        "Factory",
        "Captured",
    ] {
        let entries = inventory
            .entries
            .iter()
            .filter(|e| e.symbol.as_deref() == Some(name))
            .collect::<Vec<_>>();
        assert!(!entries.is_empty(), "Lost {name}");
        assert!(
            entries.iter().all(|e| e.value_hint.is_none()),
            "No new Value exclusions in this increment"
        );
    }
}

#[test]
fn command_producers_respect_using_ownership_and_prior_escapes() {
    let source = r#"using System.Data.Common;
using Microsoft.Data.SqlClient;
class Review {
DbCommand command;
void Multiple(DbConnection db, string value) {
using (var command = db.CreateCommand()) { command.CommandText = "SELECT " + value; command.ExecuteScalar(); }
using (var command = db.CreateCommand()) { command.CommandText = "DELETE " + value; command.ExecuteNonQuery(); }
}
void Changed(DbConnection db, string value) { var command = db.CreateCommand(); command = Build(); command.CommandText = value; command.ExecuteScalar(); }
void Escaped(DbConnection db, string value) { var command = db.CreateCommand(); Adjust(command); command.CommandText = value; command.ExecuteScalar(); }
void Field(DbCommand command, string value) { command.CommandText = value; command.ExecuteScalar(); }
void Shadow(DbConnection db, string value) { DbCommand command = db.CreateCommand(); this.command.CommandText = value; this.command.ExecuteScalar(); }
void Initializer(DbConnection db, string value) { var command = new SqlCommand() { CommandText = value }; command.ExecuteScalar(); }
}
"#;
    let fixture = Fixture::new("owners", source);
    let result = mehscan_engine::scan_path(&fixture.0).unwrap();
    let sinks = result
        .evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-sql-command-text")
        .collect::<Vec<_>>();
    let multiple = sinks
        .iter()
        .filter(|e| e.enclosing_symbol.as_deref() == Some("Multiple"))
        .collect::<Vec<_>>();
    assert_eq!(multiple.len(), 2);
    for sink in multiple {
        let origin = sink
            .context
            .operand_facts
            .iter()
            .find(|f| f.kind == OperandFactKind::LocalOperandOrigin)
            .unwrap();
        assert_eq!(
            &source[origin.location.start.byte_offset..origin.location.end.byte_offset],
            "db.CreateCommand()"
        );
        assert!(
            !sink
                .context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary)
        );
        assert_eq!(sink.captures["command_origin"].text, "db.CreateCommand()");
        assert_eq!(sink.capability, Capability::DatabaseQuery);
    }
    for name in ["Changed", "Escaped", "Field", "Shadow"] {
        let sink = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(name))
            .unwrap();
        assert!(
            sink.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary),
            "{name}"
        );
    }
    let shadow = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("Shadow"))
        .unwrap();
    assert!(!shadow.captures.contains_key("command_origin"));
    assert!(
        shadow
            .context
            .operand_facts
            .iter()
            .any(|f| f.value == "field_or_nonlocal_receiver")
    );
    let initializer = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("Initializer"))
        .unwrap();
    assert!(
        initializer.captures["command_origin"]
            .text
            .contains("new SqlCommand()")
    );
}

#[test]
fn lookalike_command_definitions_never_receive_constructor_slot_facts() {
    let fixture = Fixture::new(
        "lookalike",
        "using Dapper; using System.Data.Common; class CommandDefinition { public CommandDefinition(string text) {} } class Review { object Run(DbConnection db, string input) { var cmd = new CommandDefinition(input); return db.Query(cmd); } }",
    );
    let result = mehscan_engine::scan_path(&fixture.0).unwrap();
    let item = result
        .evidence
        .iter()
        .find(|e| e.rule_id == "csharp-dapper-database-query")
        .unwrap();
    assert!(
        item.context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::OperandBoundary
                && f.value == "command_definition_identity")
    );
    assert!(!item.captures.contains_key("query_text"));
}
