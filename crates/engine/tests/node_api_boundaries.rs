use mehscan_core::{Capability, EvidenceKind};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new(files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!("mehscan-node-api-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for (name, source) in files {
            fs::write(root.join(name), source).unwrap();
        }
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn api_identity_and_security_operands_survive_without_lookalike_or_data_only_reviews() {
    let fixture = Fixture::new(&[
        (
            "app.js",
            r#"
const express = require('express');
const views = require('nunjucks');
const app = express();
app.get('/template', (req, res) => views.renderString(req.query.template, {}));
app.get('/compile', (req, res) => views.compile(req.body.template));
app.get('/data', (req, res) => views.renderString('Hello {{name}}', {name:req.query.name}));
app.get('/file', (req, response) => response.status(200).sendFile(req.query.file, {root:'/srv/public'}));
app.get('/download', (req, response) => response.download(req.query.path, 'report.txt', {root:'/srv/public'}));
app.get('/display', (req, response) => response.download('/srv/legal.txt', req.query.name));
app.get('/root', (req, response) => response.sendFile('legal.txt', {root:req.query.root}));
app.get('/spread', (req, response) => response.sendFile('legal.txt', {root:'/srv/public',...req.query}));
function send(req, output) { output.sendFile(req.query.file); }
app.get('/named', send);
function unknown(req, res) { res.sendFile(req.query.file); }
function shadow(views, req) { views.renderString(req.query.template); }
function nested(req) { const views = other; views.renderString(req.query.template); }
app.get('/shadow-response', (req, res) => { res = other; res.sendFile(req.query.file); });
"#,
        ),
        (
            "typed.ts",
            r#"
import type {Response as Reply, Request, RequestHandler} from 'express';
import express, {type Response as MixedReply} from 'express';
import {renderString as render} from 'nunjucks';
export function serve(req:Request, output:Reply) { output.sendFile(req.query.file); render(req.query.template, {}); }
export const download:RequestHandler = (req, output) => output.download(req.query.path);
export function mixed(req:express.Request, output:MixedReply) { output.sendFile(req.query.file); }
"#,
        ),
        (
            "environment.tsx",
            r#"
import * as views from 'nunjucks';
import type {Request} from 'express';
const env = new views.Environment();
const configured = views.configure({autoescape:true});
export function template(req:Request) { env.renderString(req.query.template); configured.renderString(req.body.template); }
"#,
        ),
        (
            "source-free-fs.js",
            "const fs = require('node:fs/promises'); function load(file) { return fs.readFile(file); } function save(file, data) { return fs.writeFile(file, data); }",
        ),
        (
            "unknown.js",
            "const nunjucks = require('nunjucks'); function background(template) { nunjucks.renderString(template); }",
        ),
        (
            "rebound.js",
            "const nunjucks = require('nunjucks'); nunjucks.renderString = other; function handler(req) { nunjucks.renderString(req.query.template); }",
        ),
        (
            "unrelated.js",
            r#"
const views = require('unrelated');
const express = require('not-express'); const app = express();
app.get('/', (req,res) => { views.renderString(req.query.template); res.sendFile(req.query.file); });
"#,
        ),
    ]);
    let inventory =
        mehscan_engine::investigation::build_review_inventory(&fixture.0, false).unwrap();
    let sinks = inventory
        .scan
        .evidence
        .iter()
        .filter(|e| {
            e.kind == EvidenceKind::Sink && e.tags.iter().any(|t| t == "exact-api-boundary")
        })
        .collect::<Vec<_>>();
    let in_file = |path: &str, capability| {
        sinks
            .iter()
            .filter(|e| e.location.path == path && e.capability == capability)
            .count()
    };
    assert_eq!(in_file("app.js", Capability::TemplateEvaluation), 3);
    assert_eq!(in_file("app.js", Capability::FilesystemRead), 6);
    assert_eq!(in_file("typed.ts", Capability::TemplateEvaluation), 1);
    assert_eq!(in_file("typed.ts", Capability::FilesystemRead), 3);
    assert_eq!(
        in_file("environment.tsx", Capability::TemplateEvaluation),
        2
    );
    assert!(!sinks.iter().any(|e| e.location.path == "unrelated.js"));
    assert!(!sinks.iter().any(|e| e.location.path == "rebound.js"));
    assert_eq!(in_file("unknown.js", Capability::TemplateEvaluation), 1);
    assert!(
        !inventory.entries.iter().any(|e| e.path == "unknown.js"),
        "sink-only API inventory must not create AI work"
    );
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.path == "source-free-fs.js"),
        "filesystem import spelling must not admit sink-only work"
    );
    let file = sinks
        .iter()
        .find(|e| {
            e.symbol_resolution
                .as_ref()
                .is_some_and(|s| s.observed == "response.status(200).sendFile")
        })
        .unwrap();
    assert_eq!(file.captures["path"].text, "req.query.file");
    assert_eq!(file.captures["root"].text, "'/srv/public'");
    assert!(
        sinks
            .iter()
            .any(|e| e.tags.iter().any(|t| t == "file-root:unresolved-options")),
        "spreads must not establish a trusted root"
    );
    let display = sinks
        .iter()
        .find(|e| {
            e.captures
                .get("path")
                .is_some_and(|c| c.text == "'/srv/legal.txt'")
        })
        .unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.path == display.location.path
                && e.line == display.location.start.line
                && e.capability == display.capability),
        "display filename is not a filesystem path"
    );
    let root = sinks
        .iter()
        .find(|e| {
            e.captures
                .get("root")
                .is_some_and(|c| c.text == "req.query.root")
        })
        .unwrap();
    assert!(
        inventory
            .entries
            .iter()
            .any(|e| e.path == root.location.path
                && e.line == root.location.start.line
                && e.capability == root.capability),
        "dynamic root must survive a fixed child filename"
    );
    let constant_template = sinks
        .iter()
        .find(|e| {
            e.captures
                .get("template")
                .is_some_and(|c| c.text.starts_with("'Hello"))
        })
        .unwrap();
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.path == constant_template.location.path
                && e.line == constant_template.location.start.line
                && e.capability == constant_template.capability),
        "template data is not template source: {:#?}",
        inventory
            .entries
            .iter()
            .filter(|e| e.path == constant_template.location.path
                && e.line == constant_template.location.start.line)
            .collect::<Vec<_>>()
    );
    for capability in [Capability::TemplateEvaluation, Capability::FilesystemRead] {
        assert!(
            inventory
                .scan
                .security_paths
                .iter()
                .any(|p| p.capability == capability),
            "missing native source-to-operand path for {capability:?}"
        );
    }
}
