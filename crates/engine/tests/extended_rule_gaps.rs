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

#[test]
fn typed_xpath_boundaries_preserve_the_expression_operand() {
    let root = std::env::temp_dir().join(format!("mehscan-xpath-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("Probe.cs"),
        "using System.Xml.XPath; class Other { public void Select(string value) {} } class Probe { void Run(XPathNavigator navigator, Other other, string expression) { navigator.Select(expression); other.Select(expression); } }",
    )
    .unwrap();
    std::fs::write(
        root.join("Probe.java"),
        "import javax.xml.xpath.XPath; class Other { void evaluate(String value, Object item) {} } class Probe { void run(XPath xpath, Other other, String expression) throws Exception { xpath.evaluate(expression, null); other.evaluate(expression, null); } }",
    )
    .unwrap();

    let result = mehscan_engine::scan_path(&root).unwrap();
    for path in ["Probe.cs", "Probe.java"] {
        let matches = result
            .evidence
            .iter()
            .filter(|item| item.location.path == path && item.capability == Capability::XpathQuery)
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1, "{path}: {matches:#?}");
        assert_eq!(matches[0].captures["expression"].text, "expression");
        assert!(
            matches[0]
                .tags
                .iter()
                .any(|tag| tag == "review-origin:decision-critical")
        );
    }

    let reviews =
        mehscan_engine::investigation::build_path_review_jobs(&root, Some(8), Some(100)).unwrap();
    assert!(reviews.observation_reviews.iter().all(|review| {
        review
            .review_basis
            .as_ref()
            .is_none_or(|basis| basis.relationship != "bounded_xpath_expression_interpretation")
            || !review.decision_facts.unresolved.is_empty()
    }));
    assert!(reviews.observation_reviews.iter().any(|review| {
        review
            .review_basis
            .as_ref()
            .is_some_and(|basis| basis.relationship == "bounded_xpath_expression_interpretation")
    }));
    std::fs::remove_dir_all(&root).unwrap();
}
