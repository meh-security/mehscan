use mehscan_core::OperandFactKind;
use std::{fs, path::PathBuf};
struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, source: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "mehscan-python-operands-{label}-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("review.py"), source).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn shell_options_are_source_located_and_private_reuse_stops_at_unknown_edges() {
    let source = r#"import subprocess
from subprocess import run as launch
def enabled(value):
    options = {'shell': True, 'text': True}
    return subprocess.run('echo ' + value, **options)
def disabled(value):
    options = {'shell': False}
    return launch(['/usr/bin/printf', '%s', value], **options)
def inline(value):
    return subprocess.run(value, **{'shell': True})
def direct(value):
    return subprocess.run(['echo', 'shell=True', value], shell=False)
def dynamic(value, flag):
    options = {'shell': flag}
    return subprocess.run(value, **options)
def mutated(value):
    options = {'shell': True}
    options['shell'] = False
    return subprocess.run(value, **options)
def changed(value):
    options = {'shell': True}
    options = factory()
    return subprocess.run(value, **options)
def aliased(value):
    options = {'shell': True}
    other = options
    change(other)
    return subprocess.run(value, **options)
def escaped(value):
    options = {'shell': True}
    change(options)
    return subprocess.run(value, **options)
def captured(value):
    options = {'shell': True}
    def change():
        options['shell'] = False
    change()
    return subprocess.run(value, **options)
def branch(value, flag):
    if flag:
        options = {'shell': True}
    return subprocess.run(value, **options)
def merged(value, extra):
    options = {'shell': False, **extra}
    return subprocess.run(value, **options)
def duplicates(value):
    options = {'shell': False, 'shell': True}
    return subprocess.run(value, **options)
def multiple(value, extra):
    return subprocess.run(value, **{'shell': False}, **extra)
def computed(value, key):
    options = {key: False}
    return subprocess.run(value, **options)
def factory(value):
    options = policy(value)
    return subprocess.run(value, **options)
def loop(value):
    options = {'shell': False}
    for options in policies():
        pass
    return subprocess.run(value, **options)
def sequence(value):
    return subprocess.run(['printf "%s" "$1"', 'service', value], shell=True)
def replacement(value):
    options = {'shell': False, 'executable': value}
    return subprocess.run(['/usr/bin/printf', '%s', value], **options)
def collision(value):
    return subprocess.run(value, shell=False, **{'shell': True})
def global_options(value):
    return subprocess.run(value, **GLOBAL_OPTIONS)
def argument_mutation(value):
    options = {'shell': False}
    return subprocess.run(change(options), **options)
def interpreter(value):
    return subprocess.run(['/bin/sh', '-c', 'echo ' + value], shell=False)
def interpreter_default(value):
    return subprocess.run(['/bin/sh', '-c', 'echo ' + value])
def interpreter_replacement(value):
    return subprocess.run(['/bin/sh', '-c', 'echo ' + value], shell=False, executable='/usr/bin/printf')
def interpreter_expanded(value):
    return subprocess.run(['/bin/sh', '-c', *value], shell=False)
def quoted_key(value):
    return subprocess.run(value, **{'"shell"': True})
def quoted_program(value):
    return subprocess.run(['"sh"', '-c', value], shell=False)
"#;
    let fixture = Fixture::new("options", source);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    assert_eq!(scan.coverage.totals.parse_failed, 0);
    let sinks = scan
        .evidence
        .iter()
        .filter(|e| e.rule_id == "python-process-execution")
        .collect::<Vec<_>>();
    assert_eq!(sinks.len(), 28);
    for (name, expected) in [
        ("enabled", "true"),
        ("disabled", "false"),
        ("inline", "true"),
        ("direct", "false"),
        ("dynamic", "unresolved"),
    ] {
        let item = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(name))
            .unwrap();
        let fact = item
            .context
            .operand_facts
            .iter()
            .find(|f| f.kind == OperandFactKind::ProcessShellMode)
            .unwrap();
        assert_eq!(fact.value, expected, "{name}");
        assert_eq!(
            &source[fact.location.start.byte_offset..fact.location.end.byte_offset],
            item.captures["shell_mode"].text
        );
        assert_eq!(
            item.tags.iter().any(|t| t == "shell-command-text"),
            expected == "true",
            "{name}"
        );
    }
    for name in [
        "mutated",
        "changed",
        "aliased",
        "escaped",
        "captured",
        "branch",
        "merged",
        "duplicates",
        "multiple",
        "computed",
        "factory",
        "loop",
        "collision",
        "global_options",
        "argument_mutation",
    ] {
        let item = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(name))
            .unwrap();
        assert!(
            !item
                .context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::ProcessShellMode),
            "{name}"
        );
        assert!(
            item.context
                .operand_facts
                .iter()
                .any(|f| f.kind == OperandFactKind::OperandBoundary),
            "{name}"
        );
        assert!(
            item.tags
                .iter()
                .any(|t| t == "process-invocation:unresolved-shell"),
            "{name}"
        );
    }
    let enabled = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("enabled"))
        .unwrap();
    assert_eq!(enabled.captures["command"].text, "'echo ' + value");
    assert_eq!(
        enabled.captures["shell_command"],
        enabled.captures["command"]
    );
    let sequence = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("sequence"))
        .unwrap();
    assert_eq!(
        sequence.captures["posix_shell_command"].text,
        "'printf \"%s\" \"$1\"'"
    );
    assert!(!sequence.captures.contains_key("shell_command"));
    let replacement = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("replacement"))
        .unwrap();
    assert_eq!(replacement.captures["executable"].text, "value");
    assert_eq!(
        replacement.captures["command"].text,
        "['/usr/bin/printf', '%s', value]"
    );
    for name in ["interpreter", "interpreter_default"] {
        let item = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(name))
            .unwrap();
        assert_eq!(item.captures["shell_command"].text, "'echo ' + value");
        assert_eq!(item.captures["executable"].text, "'/bin/sh'");
        assert!(
            item.tags
                .iter()
                .any(|t| t == "process-invocation:shell-command")
        );
    }
    for name in [
        "interpreter_replacement",
        "interpreter_expanded",
        "quoted_program",
    ] {
        let item = sinks
            .iter()
            .find(|e| e.enclosing_symbol.as_deref() == Some(name))
            .unwrap();
        assert!(!item.captures.contains_key("shell_command"));
    }
    let quoted_key = sinks
        .iter()
        .find(|e| e.enclosing_symbol.as_deref() == Some("quoted_key"))
        .unwrap();
    assert!(
        !quoted_key
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::ProcessShellMode)
    );
    assert!(
        enabled
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::LocalOperandOrigin)
    );
    assert!(
        sinks
            .iter()
            .all(|e| !e.tags.iter().any(|t| t.starts_with("value-scope:")))
    );
}

#[test]
fn observed_process_method_writes_leave_callable_contract_open() {
    let source = "import subprocess\nsubprocess.run = adapter\ndef invoke(value):\n    return subprocess.run(value, shell=False)\n";
    let fixture = Fixture::new("method", source);
    let scan = mehscan_engine::scan_path(&fixture.0).unwrap();
    let item = scan
        .evidence
        .iter()
        .find(|e| e.rule_id == "python-process-execution")
        .unwrap();
    assert!(
        !item
            .context
            .operand_facts
            .iter()
            .any(|f| f.kind == OperandFactKind::ProcessShellMode)
    );
    let boundary = item
        .context
        .operand_facts
        .iter()
        .find(|f| f.value == "observed_process_method_write")
        .unwrap();
    assert_eq!(
        &source[boundary.location.start.byte_offset..boundary.location.end.byte_offset],
        "subprocess.run"
    );
}
