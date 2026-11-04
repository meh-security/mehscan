mod support;
use mehscan_core::{Capability, EvidenceKind};
use std::fs;

fn check(extension: &str, source: &str, expected: Option<Capability>, unknown: bool) {
    let root = support::temp_dir("filesystem-api-modes");
    fs::write(root.join(format!("app.{extension}")), source).unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0, "{source}");
    let effects = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind != EvidenceKind::Source
                && matches!(
                    e.capability,
                    Capability::FilesystemRead | Capability::FilesystemWrite
                )
                && e.cwe_candidates.iter().any(|c| c == "CWE-22")
        })
        .collect::<Vec<_>>();
    if let Some(capability) = expected {
        assert!(
            effects.iter().any(|e| e.capability == capability),
            "missing {capability:?}: {source}\n{effects:#?}"
        );
        assert_eq!(
            effects
                .iter()
                .any(|e| e.tags.iter().any(|t| t == "filesystem-mode:unresolved")),
            unknown,
            "{source}\n{effects:#?}"
        );
        assert!(
            effects.iter().all(|e| e.captures.contains_key("path")),
            "{source}"
        );
    } else {
        assert!(
            effects.is_empty(),
            "unproven SDK owner: {source}\n{effects:#?}"
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn node_opens_respect_packages_flags_and_aliases_in_all_frontends() {
    for extension in ["js", "ts", "tsx"] {
        for (expression, capability, unknown) in [
            ("fs.openSync(path,'r')", Capability::FilesystemRead, false),
            ("fs.openSync(path,'r+')", Capability::FilesystemWrite, false),
            (
                "fs.open(path,mode,callback)",
                Capability::FilesystemRead,
                true,
            ),
            (
                "fs.readFileSync(path,{flag:'w+'})",
                Capability::FilesystemWrite,
                false,
            ),
            (
                "fs.createReadStream(path,{flags:'a+'})",
                Capability::FilesystemWrite,
                false,
            ),
            (
                "fs.readFileSync(path,options)",
                Capability::FilesystemRead,
                true,
            ),
            (
                "fs.readFileSync(path,{...options})",
                Capability::FilesystemRead,
                true,
            ),
            (
                "fs.writeFileSync(path,data,{flag:'r'})",
                Capability::FilesystemWrite,
                false,
            ),
        ] {
            check(
                extension,
                &format!(
                    "import * as fs from 'node:fs'; function operation(path,mode,callback,options,data){{return {expression};}}"
                ),
                Some(capability),
                unknown,
            );
        }
        check(
            extension,
            "import {open as acquire} from 'node:fs/promises'; function operation(path){return acquire(path,'a');}",
            Some(Capability::FilesystemWrite),
            false,
        );
        check(
            extension,
            "const files = require('fs'); function operation(path){return files.openSync(path,'w');}",
            Some(Capability::FilesystemWrite),
            false,
        );
        check(
            extension,
            "function operation(path){const files=require('node:fs');return files.openSync(path,'w');}",
            Some(Capability::FilesystemWrite),
            false,
        );
        check(
            extension,
            "function unrelated(){const files=require('custom/files');}function operation(path){const files=require('node:fs');return files.openSync(path,'r');}",
            Some(Capability::FilesystemRead),
            false,
        );
        for source in [
            "import * as fs from 'custom/files'; function operation(path){return fs.readFileSync(path);}",
            "import fs from 'fs-extra/esm'; function operation(path){return fs.readFileSync(path);}",
            "import * as fs from 'node:fs'; function operation(fs,path){return fs.readFileSync(path);}",
            "import * as fs from 'node:fs'; function operation(path){fs.readFileSync=custom;return fs.readFileSync(path);}",
            "function unrelated(){const fs=require('node:fs');}function operation(fs,path){return fs.readFileSync(path);}",
        ] {
            check(extension, source, None, false);
        }
    }
}

#[test]
fn node_compatible_filesystem_packages_keep_only_their_documented_core_exports() {
    for extension in ["js", "ts", "tsx"] {
        for package in ["fs-extra", "graceful-fs"] {
            check(
                extension,
                &format!(
                    "import files from '{package}'; function operation(path){{return files.readFileSync(path);}}"
                ),
                Some(Capability::FilesystemRead),
                false,
            );
            check(
                extension,
                &format!(
                    "const files=require('{package}'); function operation(path){{return files.openSync(path,'w');}}"
                ),
                Some(Capability::FilesystemWrite),
                false,
            );
            check(
                extension,
                &format!(
                    "import files from '{package}'; function operation(path){{return files.readFileSync(path,{{flag:'w+'}});}}"
                ),
                Some(Capability::FilesystemWrite),
                false,
            );
        }
    }
}

#[test]
fn filesystem_helper_contracts_keep_mutating_read_flags_and_open_effects() {
    let root = support::temp_dir("filesystem-helper-open");
    fs::write(root.join("app.js"), "import * as fs from 'node:fs';export function open_file(path){return fs.openSync(path,'w');}export function read_file(path){return fs.readFileSync(path,{flag:'w+'});}export function endpoint(req){open_file(req.query.first);return read_file(req.query.second);}").unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    for (call, operand) in [
        ("open_file(req.query.first)", "req.query.first"),
        ("read_file(req.query.second)", "req.query.second"),
    ] {
        assert!(
            inventory
                .scan
                .evidence
                .iter()
                .any(|e| e.capability == Capability::FilesystemWrite
                    && e.captures.values().any(|c| c.text == operand)
                    && e.enclosing_symbol.as_deref() == Some("endpoint")),
            "missing helper effect {call}: {:#?}",
            inventory
                .scan
                .evidence
                .iter()
                .filter(|e| e.capability == Capability::FilesystemWrite)
                .collect::<Vec<_>>()
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_open_modes_keep_path_authority_in_the_question_after_effect_resolution() {
    let root = support::temp_dir("filesystem-mode-question");
    fs::write(root.join("App.cs"), "class App{object Operation(string path,System.IO.FileStreamOptions options){return new System.IO.FileStream(path,options);}}").unwrap();
    fs::write(
        root.join("app.py"),
        "def operation(path,mode):\n return open(path,mode)\n",
    )
    .unwrap();
    let inventory = mehscan_engine::investigation::build_review_inventory(&root, false).unwrap();
    let ids = inventory
        .entries
        .iter()
        .filter(|e| {
            matches!(
                e.capability,
                Capability::FilesystemRead | Capability::FilesystemWrite
            )
        })
        .map(|e| e.review_id.clone())
        .collect();
    let job =
        mehscan_engine::investigation::build_selected_review_jobs(&root, &inventory, &ids, None)
            .unwrap();
    assert_eq!(job.observation_reviews.len(), 2);
    for review in &job.observation_reviews {
        assert!(review.title.contains("unresolved open mode"));
        let question = &review.review_basis.as_ref().unwrap().security_question;
        assert!(question.contains("creation, truncation or write"));
        assert!(question.contains("authority or root"));
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn python_builtin_sdk_and_path_opens_preserve_effects_and_shadowing() {
    for (imports, expression, capability, unknown) in [
        ("", "open(path,'r+')", Capability::FilesystemWrite, false),
        (
            "",
            "open(file=path,mode='w')",
            Capability::FilesystemWrite,
            false,
        ),
        ("", "open(path,mode)", Capability::FilesystemRead, true),
        (
            "from io import open as acquire\n",
            "acquire(path,'a')",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "import codecs\n",
            "codecs.open(path,'r+')",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "from pathlib import Path\n",
            "Path(path).open('w')",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "from pathlib import Path\n",
            "Path(path).open()",
            Capability::FilesystemRead,
            false,
        ),
    ] {
        check(
            "py",
            &format!("{imports}def operation(path,mode):\n    return {expression}\n"),
            Some(capability),
            unknown,
        );
    }
    check(
        "py",
        "def unrelated():\n    from custom import open\ndef operation(path):\n    return open(path,'r')\n",
        Some(Capability::FilesystemRead),
        false,
    );
    check(
        "py",
        "def operation(path):\n    from io import open as acquire\n    return acquire(path,'w')\n",
        Some(Capability::FilesystemWrite),
        false,
    );
    for source in [
        "def operation(path):\n    def open(path,mode): return None\n    return open(path,'r')\n",
        "from custom import open\ndef operation(path):\n    return open(path,'r')\n",
        "import io\ndef operation(io,path):\n    return io.open(path,'r')\n",
        "def unrelated():\n    from io import open as acquire\ndef operation(path):\n    return acquire(path,'r')\n",
    ] {
        check("py", source, None, false);
    }
}

#[test]
fn native_stdio_posix_and_stream_modes_use_sdk_identity() {
    for extension in ["c", "cpp"] {
        for (expression, capability, unknown) in [
            ("fopen(path,\"r+\")", Capability::FilesystemWrite, false),
            ("fopen(path,\"ab\")", Capability::FilesystemWrite, false),
            ("fopen(path,mode)", Capability::FilesystemRead, true),
            (
                "open(path,O_RDONLY|O_NONBLOCK)",
                Capability::FilesystemRead,
                false,
            ),
            (
                "open(path,O_WRONLY|O_CREAT,0600)",
                Capability::FilesystemWrite,
                false,
            ),
            (
                "openat(directory,path,flags,0600)",
                Capability::FilesystemRead,
                true,
            ),
        ] {
            check(
                extension,
                &format!(
                    "#include <stdio.h>\n#include <fcntl.h>\nvoid operation(const char *path,const char *mode,int flags,int directory){{{expression};}}"
                ),
                Some(capability),
                unknown,
            );
        }
        check(
            extension,
            "static int fopen(const char*p,const char*m){return 0;} void operation(const char*path){fopen(path,\"r\");}",
            None,
            false,
        );
    }
    for (expression, capability) in [
        ("std::fopen(path,\"r\");", Capability::FilesystemRead),
        ("std::ifstream file(path);", Capability::FilesystemRead),
        ("std::ofstream file(path);", Capability::FilesystemWrite),
        (
            "std::fstream file(path,std::ios::in|std::ios::out);",
            Capability::FilesystemWrite,
        ),
    ] {
        check(
            "cpp",
            &format!(
                "#include <cstdio>\n#include <fstream>\nvoid operation(const char*path){{{expression}}}"
            ),
            Some(capability),
            false,
        );
    }
}

#[test]
fn dotnet_and_jvm_opens_keep_defaults_dynamic_modes_and_owners() {
    for (expr, capability, unknown) in [
        (
            "System.IO.File.Open(path,System.IO.FileMode.Open,System.IO.FileAccess.Read)",
            Capability::FilesystemRead,
            false,
        ),
        (
            "new System.IO.FileStream(path,System.IO.FileMode.Open)",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "new System.IO.FileStream(mode: System.IO.FileMode.Open, path: path, access: System.IO.FileAccess.Read)",
            Capability::FilesystemRead,
            false,
        ),
        (
            "new System.IO.FileStream(path,mode)",
            Capability::FilesystemRead,
            true,
        ),
    ] {
        check(
            "cs",
            &format!(
                "class App{{object Operation(string path,System.IO.FileMode mode){{return {expr};}}}}"
            ),
            Some(capability),
            unknown,
        );
    }
    check(
        "cs",
        "class FileStream{public FileStream(string path,System.IO.FileMode mode){}} class App{object Operation(string path){return new FileStream(path,System.IO.FileMode.Open);}}",
        None,
        false,
    );
    for (expr, capability, unknown) in [
        (
            "FileChannel.open(path,StandardOpenOption.READ)",
            Capability::FilesystemRead,
            false,
        ),
        (
            "FileChannel.open(path,StandardOpenOption.WRITE,StandardOpenOption.CREATE)",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "Files.newByteChannel(path,StandardOpenOption.WRITE,StandardOpenOption.CREATE)",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "Files.newByteChannel(path,options)",
            Capability::FilesystemRead,
            true,
        ),
    ] {
        check(
            "java",
            &format!(
                "import java.nio.file.*; import java.nio.channels.FileChannel; class App{{Object operation(Path path,OpenOption[] options)throws Exception{{return {expr};}}}}"
            ),
            Some(capability),
            unknown,
        );
    }
    for (expr, capability, unknown) in [
        (
            "java.io.FileInputStream(path)",
            Capability::FilesystemRead,
            false,
        ),
        (
            "java.io.FileOutputStream(path)",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "java.io.RandomAccessFile(path,\"rw\")",
            Capability::FilesystemWrite,
            false,
        ),
        (
            "java.io.RandomAccessFile(path,mode)",
            Capability::FilesystemRead,
            true,
        ),
    ] {
        check(
            "kt",
            &format!("fun operation(path:String,mode:String) = {expr}"),
            Some(capability),
            unknown,
        );
    }
}

#[test]
fn php_canonical_opens_and_go_ownership_preserve_conservative_identity() {
    for (expr, capability, unknown) in [
        ("\\fopen($path,'r')", Capability::FilesystemRead, false),
        ("\\fopen($path,'r+')", Capability::FilesystemWrite, false),
        ("\\fopen($path,$mode)", Capability::FilesystemRead, true),
    ] {
        check(
            "php",
            &format!("<?php namespace App; function operation($path,$mode){{return {expr};}}"),
            Some(capability),
            unknown,
        );
    }
    check(
        "php",
        "<?php namespace App; use function fopen as acquire; function operation($path){return acquire($path,'w');}",
        Some(Capability::FilesystemWrite),
        false,
    );
    check(
        "php",
        "<?php namespace App; function fopen($p,$m){} function operation($path){return fopen($path,'r');}",
        None,
        false,
    );
    check(
        "go",
        "package app\nimport files \"os\"\nfunc operation(path string){files.OpenFile(path,files.O_RDWR|files.O_CREATE,0600)}",
        Some(Capability::FilesystemWrite),
        false,
    );
    check(
        "go",
        "package app\ntype Service struct{}\nfunc(s Service)Open(p string){}\nfunc operation(os Service,path string){os.Open(path)}",
        None,
        false,
    );
}
