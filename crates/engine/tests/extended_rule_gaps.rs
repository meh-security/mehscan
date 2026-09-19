use mehscan_core::Capability;

#[test]
fn extended_standard_library_boundaries_preserve_security_sensitive_operands() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-extended-boundaries-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let cases = [
        (
            "Probe.cs",
            "class Probe { void Run(string source, string target) { System.IO.Directory.Move(source, target); } }",
            Capability::FilesystemWrite,
            "target",
            1,
            0,
        ),
        (
            "Probe.java",
            "import java.nio.file.Files; import java.nio.file.Path; class Probe { void run(Path source, Path target) throws Exception { Files.copy(source, target); Files.delete(target); Files.createDirectories(target); } }",
            Capability::FilesystemWrite,
            "target",
            3,
            1,
        ),
        (
            "app.js",
            "const fs = require('fs'); const vm = require('vm'); function run(source, target, code) { fs.renameSync(source, target); fs.copyFileSync(source, target); fs.rmSync(target); vm.compileFunction(code, []); new vm.Script(code); new vm.SourceTextModule(code); }",
            Capability::FilesystemWrite,
            "target",
            3,
            1,
        ),
        (
            "app.ts",
            "import fs from 'fs'; import vm from 'vm'; function run(source: string, target: string, code: string) { fs.renameSync(source, target); fs.copyFileSync(source, target); fs.rmSync(target); vm.compileFunction(code, []); new vm.Script(code); new vm.SourceTextModule(code); }",
            Capability::FilesystemWrite,
            "target",
            3,
            1,
        ),
        (
            "app.tsx",
            "import fs from 'fs'; import vm from 'vm'; function run(source: string, target: string, code: string) { fs.renameSync(source, target); fs.copyFileSync(source, target); fs.rmSync(target); vm.compileFunction(code, []); new vm.Script(code); new vm.SourceTextModule(code); }",
            Capability::FilesystemWrite,
            "target",
            3,
            1,
        ),
        (
            "app.py",
            "import pathlib, shutil, marshal, dill, jsonpickle\ndef run(source, target, payload):\n    shutil.copy(source, target)\n    pathlib.Path(target).write_text(payload)\n    pathlib.Path(target).unlink()\n    marshal.loads(payload)\n    dill.loads(payload)\n    jsonpickle.decode(payload)\n",
            Capability::FilesystemWrite,
            "target",
            3,
            1,
        ),
        (
            "app.go",
            "package app\nimport \"os\"\nfunc run(source, target string) { os.Rename(source, target); os.RemoveAll(target); os.MkdirAll(target, 0755) }",
            Capability::FilesystemWrite,
            "target",
            3,
            0,
        ),
        (
            "app.rs",
            "fn run(source: &str, target: &str) { std::fs::copy(source, target); std::fs::rename(source, target); std::fs::create_dir_all(target); std::fs::remove_dir(target); }",
            Capability::FilesystemWrite,
            "target",
            4,
            1,
        ),
        (
            "app.kt",
            "import java.nio.file.Files\nimport java.nio.file.Path\nfun run(source: Path, target: Path) { Files.copy(source, target); Files.delete(target); Files.createDirectories(target) }",
            Capability::FilesystemWrite,
            "target",
            3,
            1,
        ),
        (
            "app.c",
            "void run(char *source, char *target) { rename(source, target); }",
            Capability::FilesystemWrite,
            "target",
            1,
            0,
        ),
        (
            "app.cpp",
            "void run(char *source, char *target) { rename(source, target); }",
            Capability::FilesystemWrite,
            "target",
            1,
            0,
        ),
        (
            "app.php",
            "<?php function run($source, $target) { rename($source, $target); }",
            Capability::FilesystemWrite,
            "$target",
            1,
            0,
        ),
    ];
    for (path, source, _, _, _, _) in cases {
        std::fs::write(root.join(path), source).unwrap();
    }
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert_eq!(result.coverage.totals.parse_failed, 0);
    for (path, _, capability, operand, expected, expected_reads) in cases {
        let evidence = result
            .evidence
            .iter()
            .filter(|item| {
                item.location.path == path
                    && item.capability == capability
                    && (item.rule_id.ends_with("filesystem-write")
                        || item.rule_id == "kotlin-files-write")
            })
            .collect::<Vec<_>>();
        assert_eq!(evidence.len(), expected, "{path}: {evidence:#?}");
        assert!(
            evidence
                .iter()
                .all(|item| item.captures["path"].text == operand),
            "{path}: {evidence:#?}"
        );
        let reads = result
            .evidence
            .iter()
            .filter(|item| {
                item.location.path == path
                    && item.capability == Capability::FilesystemRead
                    && (item.rule_id.ends_with("filesystem-read")
                        || item.rule_id == "kotlin-files-read")
            })
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), expected_reads, "{path}: {reads:#?}");
        assert!(
            reads
                .iter()
                .all(|item| item.captures["path"].text.trim_start_matches('$') == "source"),
            "{path}: {reads:#?}"
        );
    }
    for path in ["app.js", "app.ts", "app.tsx"] {
        let dynamic = result
            .evidence
            .iter()
            .filter(|item| {
                item.location.path == path && item.capability == Capability::DynamicCodeExecution
            })
            .collect::<Vec<_>>();
        assert_eq!(dynamic.len(), 3, "{path}: {dynamic:#?}");
        assert!(
            dynamic
                .iter()
                .all(|item| item.captures["code"].text == "code")
        );
    }
    let deserialization = result
        .evidence
        .iter()
        .filter(|item| {
            item.location.path == "app.py" && item.capability == Capability::Deserialization
        })
        .collect::<Vec<_>>();
    assert_eq!(deserialization.len(), 3, "{deserialization:#?}");
    assert!(
        deserialization
            .iter()
            .all(|item| item.captures["payload"].text == "payload")
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn similarly_named_receivers_are_not_extended_boundaries() {
    let root = std::env::temp_dir().join(format!(
        "mehscan-extended-lookalikes-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.js"), "function run(fake, source, target, code) { fake.copyFileSync(source, target); fake.compileFunction(code, []); new fake.Script(code); }").unwrap();
    std::fs::write(
        root.join("app.py"),
        "def run(codec, payload):\n    codec.loads(payload)\n    codec.decode(payload)\n",
    )
    .unwrap();
    let result = mehscan_engine::scan_path(&root).unwrap();
    assert!(!result.evidence.iter().any(|item| matches!(
        item.capability,
        Capability::FilesystemWrite
            | Capability::DynamicCodeExecution
            | Capability::Deserialization
    )));
    std::fs::remove_dir_all(&root).unwrap();
}
