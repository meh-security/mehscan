//! Bounded file-content relationships. These are navigation/equality facts,
//! never evidence that a writer reaches a read or that indexed bytes are served.
use super::*;
use sha2::{Digest, Sha256};

const MAX_WRITERS: usize = 2;
const MAX_MATCHES: usize = 2;
const MAX_KEYS: usize = 16;
const MAX_FILES: usize = 256;
const MAX_FILE_BYTES: usize = 256 * 1024;
const MAX_ROOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ROOTS: usize = 16;
const MAX_ASSIGNMENT_BYTES: usize = 2 * 1024;

#[derive(Clone)]
struct KeyCopy {
    copy: Location,
    definition: Location,
    signer: Location,
    digest: String,
}

pub(super) struct Index<'a> {
    reads: BTreeMap<String, Vec<&'a Evidence>>,
    writers: Vec<ReviewNeighborhoodFact>,
    writer_limited: bool,
    copies: BTreeMap<String, Vec<KeyCopy>>,
    limited_roots: BTreeSet<String>,
}

impl<'a> Index<'a> {
    pub(super) fn build(
        sources: &RepositorySources,
        evidence: &'a [Evidence],
        groups: &[ObservationGroup],
    ) -> Self {
        let mut index = Self {
            reads: BTreeMap::new(),
            writers: Vec::new(),
            writer_limited: false,
            copies: BTreeMap::new(),
            limited_roots: BTreeSet::new(),
        };
        let parser_paths = groups
            .iter()
            .filter(|g| {
                g.evidence
                    .iter()
                    .any(|e| e.capability == Capability::Deserialization)
            })
            .map(|g| g.path.as_str())
            .collect::<BTreeSet<_>>();
        if !parser_paths.is_empty() {
            for item in evidence {
                if item.capability == Capability::FilesystemRead
                    && parser_paths.contains(item.location.path.as_str())
                {
                    index
                        .reads
                        .entry(item.location.path.clone())
                        .or_default()
                        .push(item);
                }
                if item.kind != EvidenceKind::Sink
                    || item.capability != Capability::FilesystemWrite
                    || !item.rule_id.ends_with("archive-raw-path-write")
                {
                    continue;
                }
                if index.writers.len() == MAX_WRITERS {
                    index.writer_limited = true;
                    continue;
                }
                let Ok(file) = sources.file(&item.location.path) else {
                    continue;
                };
                let Ok((slice, cut)) = review_source_slice(
                    file,
                    item.location.start.line.saturating_sub(9).max(1),
                    item.location.end.line.saturating_add(22),
                    &item.location,
                ) else {
                    continue;
                };
                index.writer_limited |= cut;
                index.writers.push(ReviewNeighborhoodFact {
                    role: "possible_file_content_writer_context".into(), symbol: item.rule_id.clone(),
                    location: slice.location, excerpt: slice.text, evidence_id: Some(item.id.clone()),
                    provenance: textual_provenance("observed archive writer; read target, invocation and gates are unverified 1"),
                });
            }
        }
        let roots = groups
            .iter()
            .flat_map(|g| &g.evidence)
            .filter_map(directory_root)
            .collect::<BTreeSet<_>>();
        if roots.is_empty() {
            return index;
        }
        // Only source files with a recorded signing operation contribute keys.
        // Co-location is not proof of which binding the operation consumes.
        let mut keys = BTreeMap::<String, Vec<(Location, Location)>>::new();
        let mut key_count = 0;
        let mut keys_limited = false;
        let mut signing_files = BTreeSet::new();
        let mut signing_bytes = 0usize;
        for signer in evidence
            .iter()
            .filter(|e| e.capability == Capability::TokenGeneration)
        {
            if signing_files.len() == MAX_FILES || signing_bytes >= MAX_ROOT_BYTES {
                keys_limited = true;
                break;
            }
            if !signing_files.insert(signer.location.path.clone()) {
                continue;
            }
            let Ok(file) = sources.file(&signer.location.path) else {
                continue;
            };
            if file.source.len() > MAX_FILE_BYTES
                || signing_bytes + file.source.len() > MAX_ROOT_BYTES
            {
                keys_limited = true;
                continue;
            }
            signing_bytes += file.source.len();
            let found = private_keys(&file.source);
            keys_limited |= found.len() == MAX_KEYS;
            for (start, end, digest) in found {
                if key_count == MAX_KEYS {
                    keys_limited = true;
                    break;
                }
                keys.entry(digest).or_default().push((
                    location_from_offsets(&file.path, &file.source, start, end),
                    signer.location.clone(),
                ));
                key_count += 1;
            }
        }
        for (root_number, root) in roots.into_iter().enumerate() {
            if root_number >= MAX_ROOTS {
                index.limited_roots.insert(root);
                continue;
            }
            if keys_limited {
                index.limited_roots.insert(root.clone());
            }
            let mut count = 0;
            let mut bytes = 0;
            let mut matches = Vec::new();
            for file in sources
                .files
                .values()
                .filter(|f| in_root(&f.path, &root) && !is_sast_excluded_source(Path::new(&f.path)))
            {
                if count == MAX_FILES || bytes + file.source.len() > MAX_ROOT_BYTES {
                    index.limited_roots.insert(root.clone());
                    break;
                }
                count += 1;
                bytes += file.source.len();
                if file.source.len() > MAX_FILE_BYTES {
                    index.limited_roots.insert(root.clone());
                    continue;
                }
                let found = private_keys(&file.source);
                if found.len() == MAX_KEYS {
                    index.limited_roots.insert(root.clone());
                }
                for (start, end, digest) in found {
                    for (definition, signer) in keys.get(&digest).into_iter().flatten() {
                        if definition.path == file.path {
                            continue;
                        }
                        if matches.len() == MAX_MATCHES {
                            index.limited_roots.insert(root.clone());
                            break;
                        }
                        matches.push(KeyCopy {
                            copy: location_from_offsets(&file.path, &file.source, start, end),
                            definition: definition.clone(),
                            signer: signer.clone(),
                            digest: digest.clone(),
                        });
                    }
                }
            }
            index.copies.insert(root, matches);
        }
        index
    }

    pub(super) fn facts(
        &self,
        sources: &RepositorySources,
        evidence: &[Evidence],
    ) -> (Vec<ReviewNeighborhoodFact>, bool) {
        let mut facts = Vec::new();
        let mut limited = false;
        for parser in evidence
            .iter()
            .filter(|e| e.capability == Capability::Deserialization)
        {
            let Some(file) = sources.file(&parser.location.path).ok() else {
                continue;
            };
            let read = self
                .reads
                .get(&parser.location.path)
                .into_iter()
                .flatten()
                .find(|read| file_payload(parser, read, file));
            let Some(read) = read else {
                continue;
            };
            if self.writers.is_empty() {
                continue;
            }
            facts.push(ReviewNeighborhoodFact {
                role: "file_content_read_context".into(), symbol: format!("file-backed {:?} operand", parser.capability),
                location: read.location.clone(), excerpt: format!(
                    "A recorded file read occurs inside this parser operand or its immediately preceding assignment at {}:{}. Filename selection does not establish content integrity. The attached archive writers are possible producers only: compare the exact destination, branch, invocation, transformations and downstream consumer.", read.location.path, read.location.start.line),
                evidence_id: Some(read.id.clone()), provenance: textual_provenance("bounded file-read/parser syntax relationship; content flow and writer compatibility unverified 1"),
            });
            facts.extend(self.writers.iter().cloned());
            limited |= self.writer_limited;
            break;
        }
        for root in evidence
            .iter()
            .filter_map(directory_root)
            .collect::<BTreeSet<_>>()
        {
            limited |= self.limited_roots.contains(&root);
            if self.limited_roots.contains(&root) {
                if let Some(anchor) = evidence
                    .iter()
                    .find_map(|e| e.captures.get("directory_root"))
                {
                    facts.push(ReviewNeighborhoodFact { role: "file_content_search_limit_context".into(),
                        symbol: "partial indexed-root private-key comparison".into(), location: anchor.location.clone(),
                        excerpt: "The bounded private-key comparison omitted files, bytes or matches. Missing matches do not prove harmless contents or a safe directory. It does not search every secret type.".into(),
                        evidence_id: None, provenance: textual_provenance("bounded auxiliary search limit, not absence evidence 1") });
                }
            }
            for copy in self.copies.get(&root).into_iter().flatten() {
                for (role, location, description) in [
                    (
                        "possible_sensitive_content_copy_context",
                        &copy.copy,
                        format!(
                            "Normalized PEM private-key bytes under the literal root mapped to the repository match {}:{}. Equality fingerprint SHA-256 {}. This is byte equality, not proof of actual file delivery or a deployed secret. Verify runtime root resolution, index/download transforms and guards.",
                            copy.definition.path, copy.definition.start.line, copy.digest
                        ),
                    ),
                    (
                        "possible_sensitive_content_definition_context",
                        &copy.definition,
                        format!(
                            "This source private-key body matches {}:{}; value omitted. A signing observation is at {}:{}. Verify that operation's actual key binding and active configuration; co-location alone does not establish use.",
                            copy.copy.path,
                            copy.copy.start.line,
                            copy.signer.path,
                            copy.signer.start.line
                        ),
                    ),
                ] {
                    facts.push(ReviewNeighborhoodFact { role: role.into(), symbol: description.clone(),
                        location: location.clone(), excerpt: description, evidence_id: None,
                        provenance: textual_provenance("bounded normalized PEM-byte equality; signing binding, delivery and deployment unverified 1") });
                }
            }
        }
        (facts, limited)
    }
}

pub(super) fn questions(facts: &[ReviewNeighborhoodFact]) -> Vec<String> {
    let mut questions = Vec::new();
    if let Some(read) = facts.iter().find(|f| f.role == "file_content_read_context") {
        questions.push(format!("Can the observed archive writer replace bytes read at {}:{} before the selected parser/consumer runs? Compare the exact target, registration/gates and invocation; filename allowlists alone do not establish contents trust.", read.location.path, read.location.start.line));
    }
    if let Some(copy) = facts
        .iter()
        .find(|f| f.role == "possible_sensitive_content_copy_context")
    {
        questions.push(format!("Does the indexed file at {}:{} reach a readable response, and does the matching source key actually supply the observed signer under active configuration? Verify transforms and guards; byte equality is not deployment or key-use proof.", copy.location.path, copy.location.start.line));
    }
    questions
}

pub(super) fn route_lookups(plan: &mut ReviewInvestigationPlan, facts: &[ReviewNeighborhoodFact]) {
    let selected = facts.iter().filter(|f| matches!(f.role.as_str(),
        "possible_file_content_writer_context" | "possible_sensitive_content_copy_context" |
        "possible_sensitive_content_definition_context")).take(2).map(|f| ReviewLookupRequest {
            operation: "source".into(),
            arguments: [("path".into(),f.location.path.clone()),
                ("start-line".into(),f.location.start.line.saturating_sub(6).max(1).to_string()),
                ("end-line".into(),f.location.end.line.saturating_add(8).to_string())].into(),
            questions: questions(facts),
            purpose: "Check the supplied file-content relationship against actual operands, active writers/consumers, transforms and guards; it is not an admitted verdict.".into(),
        }).collect::<Vec<_>>();
    if !selected.is_empty() {
        plan.lookup_requests.splice(0..0, selected);
        plan.lookup_requests.truncate(2);
    }
}

fn directory_root(e: &Evidence) -> Option<String> {
    if !e.tags.iter().any(|t| t == "directory-index") {
        return None;
    }
    let value = quoted_literal_value(e.captures.get("directory_root")?.text.trim())?;
    // Unknown escapes, absolute paths and traversal are not resolvable scan roots.
    if value.contains(['\\', ':', '$'])
        || value.starts_with('/')
        || value.is_empty()
        || value.split('/').any(|p| p == "..")
    {
        return None;
    }
    let normalized = value
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect::<Vec<_>>()
        .join("/");
    Some(normalized)
}

fn in_root(path: &str, root: &str) -> bool {
    root.is_empty() || path.strip_prefix(root).is_some_and(|s| s.starts_with('/'))
}

fn file_payload(parser: &Evidence, read: &Evidence, file: &SourceFile) -> bool {
    if parser.location.path != read.location.path {
        return false;
    }
    if parser.captures.values().any(|c| {
        c.location.start.byte_offset <= read.location.start.byte_offset
            && c.location.end.byte_offset >= read.location.end.byte_offset
    }) {
        return true;
    }
    if read.enclosing_symbol.is_none()
        || read.enclosing_symbol != parser.enclosing_symbol
        || read.location.end.byte_offset >= parser.location.start.byte_offset
        || parser.location.start.line > read.location.end.line + 3
        || parser.location.start.byte_offset - read.location.end.byte_offset > MAX_ASSIGNMENT_BYTES
    {
        return false;
    }
    let mut prefix_start = read
        .location
        .start
        .byte_offset
        .saturating_sub(MAX_ASSIGNMENT_BYTES);
    while prefix_start < file.source.len() && !file.source.is_char_boundary(prefix_start) {
        prefix_start += 1;
    }
    let Some(before) = file
        .source
        .get(prefix_start..read.location.start.byte_offset)
    else {
        return false;
    };
    let line = before.rsplit('\n').next().unwrap_or("");
    let Some((left, right)) = line.rsplit_once('=') else {
        return false;
    };
    if !right
        .split_whitespace()
        .all(|v| matches!(v, "await" | "try"))
    {
        return false;
    }
    let left = left.split(':').next().unwrap_or(left);
    let Some(name) = left
        .split_whitespace()
        .last()
        .filter(|n| is_plain_identifier(n))
    else {
        return false;
    };
    let between = &file.source[read.location.end.byte_offset..parser.location.start.byte_offset];
    let compact: String = between.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.contains(&format!("{name}=")) {
        return false;
    }
    parser.captures.values().any(|c| c.text.trim() == name)
}

fn private_keys(source: &str) -> Vec<(usize, usize, String)> {
    let mut result = Vec::new();
    for label in [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ] {
        let begin = format!("-----BEGIN {label}-----");
        let end = format!("-----END {label}-----");
        let mut offset = 0;
        while let Some(start) = source[offset..].find(&begin).map(|p| p + offset) {
            let body_start = start + begin.len();
            let Some(close) = source[body_start..].find(&end).map(|p| p + body_start) else {
                break;
            };
            offset = close + end.len();
            let body = source[body_start..close]
                .replace("\\r", "")
                .replace("\\n", "");
            let body: String = body.chars().filter(|c| !c.is_ascii_whitespace()).collect();
            if body.len() >= 64
                && body.len() <= 16384
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                result.push((
                    start,
                    offset,
                    format!("{:x}", Sha256::digest(format!("{label}:{body}"))),
                ));
            }
            if result.len() == MAX_KEYS {
                return result;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sources(files: &[(&str, &str)]) -> RepositorySources {
        RepositorySources {
            node_modules: Default::default(),
            root: "fixture".into(),
            files: files
                .iter()
                .map(|(path, text)| {
                    (
                        path.to_string(),
                        SourceFile {
                            path: path.to_string(),
                            language: Some(Language::Typescript),
                            source: text.to_string(),
                        },
                    )
                })
                .collect(),
        }
    }

    fn item(path: &str, source: &str, text: &str, capability: Capability) -> Evidence {
        let start = source.find(text).unwrap();
        Evidence {
            id: format!("{path}:{start}:{capability:?}"),
            kind: EvidenceKind::Sink,
            capability,
            location: location_from_offsets(path, source, start, start + text.len()),
            enclosing_symbol: Some("load".into()),
            captures: BTreeMap::new(),
            cwe_candidates: vec![],
            tags: vec![],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "fixture".into(),
                rule_version: 1,
            },
            context: EvidenceContext::default(),
            symbol_resolution: None,
            rule_id: "fixture".into(),
            related_evidence: vec![],
        }
    }

    fn captured(e: &mut Evidence, source: &str, name: &str, text: &str) {
        let start = source.find(text).unwrap();
        e.captures.insert(
            name.into(),
            Capture {
                text: text.into(),
                location: location_from_offsets(
                    &e.location.path,
                    source,
                    start,
                    start + text.len(),
                ),
            },
        );
    }

    fn group(e: Evidence) -> ObservationGroup {
        ObservationGroup {
            path: e.location.path.clone(),
            symbol: "load".into(),
            anchor_evidence_ids: vec![e.id.clone()],
            evidence: vec![e],
            priority: 0,
            review_material: true,
        }
    }

    fn index_route(root: &str) -> Evidence {
        let source = format!("app.use('/files', serveIndex('{root}'))");
        let mut e = item(
            "server.ts",
            &source,
            &source,
            Capability::HttpRequestHandling,
        );
        e.tags.push("directory-index".into());
        captured(&mut e, &source, "directory_root", &format!("'{root}'"));
        e
    }

    fn pem(body: char) -> String {
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
            body.to_string().repeat(96)
        )
    }

    #[test]
    fn file_content_parser_requires_a_related_read_and_keeps_writer_unproven() {
        let text = "function load() {\n const content = fs.readFileSync(path);\n return yaml.load(content);\n}";
        let mut parser = item(
            "reader.ts",
            text,
            "yaml.load(content)",
            Capability::Deserialization,
        );
        captured(&mut parser, text, "payload", "content");
        let read = item(
            "reader.ts",
            text,
            "fs.readFileSync(path)",
            Capability::FilesystemRead,
        );
        let mut writer = item(
            "writer.py",
            "write(entry.path)",
            "write(entry.path)",
            Capability::FilesystemWrite,
        );
        writer.rule_id = "python-archive-raw-path-write".into();
        let sources = sources(&[("reader.ts", text), ("writer.py", "write(entry.path)")]);
        let all = vec![parser.clone(), read.clone(), writer];
        let index = Index::build(&sources, &all, &[group(parser.clone())]);
        let (mut facts, cut) = index.facts(&sources, &[parser.clone()]);
        assert!(!cut);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[1].location.path, "writer.py");
        assert!(facts[1].provenance.engine.contains("unverified"));
        assert!(questions(&facts)[0].contains("exact target"));
        project_investigation_facts(ReviewReadiness::Investigation, &mut facts, &parser.location);
        assert!(facts.iter().all(|f| !f.excerpt.is_empty()));
        let mut plan = review_investigation_plan(
            Capability::Deserialization,
            &questions(&facts),
            &ReviewContextTruncation::default(),
            &parser.location,
            None,
        );
        route_lookups(&mut plan, &facts);
        assert_eq!(
            plan.lookup_requests[0].arguments.path.as_deref(),
            Some("writer.py")
        );
        captured(&mut parser, text, "payload", "path");
        assert!(!file_payload(
            &parser,
            &read,
            sources.file("reader.ts").unwrap()
        ));
        parser.captures.clear();
        assert!(index.facts(&sources, &[parser]).0.is_empty());
    }

    #[test]
    fn file_content_parser_accepts_nested_read_but_not_overwritten_or_other_function() {
        for (text, payload, expected) in [
            (
                "return yaml.load(await fs.readFile(path));",
                "await fs.readFile(path)",
                true,
            ),
            (
                "const content = fs.readFile(path);\ncontent = req.body;\nyaml.load(content);",
                "content",
                false,
            ),
            (
                "const content = fs.readFile(path);\nother();\nyaml.load(req.body);",
                "req.body",
                false,
            ),
        ] {
            let mut parser = item("reader.ts", text, "yaml.load", Capability::Deserialization);
            captured(&mut parser, text, "payload", payload);
            let read = item(
                "reader.ts",
                text,
                "fs.readFile(path)",
                Capability::FilesystemRead,
            );
            let file = SourceFile {
                path: "reader.ts".into(),
                language: None,
                source: text.into(),
            };
            assert_eq!(file_payload(&parser, &read, &file), expected, "{text}");
            if expected {
                let mut wrong = read.clone();
                wrong.location.path = "other.ts".into();
                assert!(!file_payload(&parser, &wrong, &file));
            }
        }
        let text = "const content = fs.readFile(path);\nyaml.load(content);";
        let mut parser = item("reader.ts", text, "yaml.load", Capability::Deserialization);
        captured(&mut parser, text, "payload", "content");
        let mut read = item(
            "reader.ts",
            text,
            "fs.readFile(path)",
            Capability::FilesystemRead,
        );
        read.enclosing_symbol = Some("other".into());
        let file = SourceFile {
            path: "reader.ts".into(),
            language: None,
            source: text.into(),
        };
        assert!(!file_payload(&parser, &read, &file));
    }

    #[test]
    fn file_content_key_equality_is_redacted_scoped_and_not_a_signing_binding() {
        let key = pem('A');
        let signer = format!(
            "const unrelatedKey = '{}';\njwt.sign(value, configuredKey);",
            key.replace('\n', "\\n")
        );
        let source = sources(&[
            ("signer.ts", &signer),
            ("downloads/key.tf", &key),
            ("downloads-other/key.tf", &key),
            ("downloads/tests/key.tf", &key),
            (
                "downloads/public.pem",
                &key.replace("PRIVATE KEY", "PUBLIC KEY"),
            ),
            ("downloads/different.pem", &pem('B')),
        ]);
        let signing = item(
            "signer.ts",
            &signer,
            "jwt.sign",
            Capability::TokenGeneration,
        );
        let route = index_route("./downloads/");
        let all = vec![signing];
        let index = Index::build(&source, &all, &[group(route.clone())]);
        let (mut facts, cut) = index.facts(&source, &[route.clone()]);
        assert!(!cut);
        assert_eq!(facts.len(), 2, "{facts:?}");
        assert_eq!(facts[0].location.path, "downloads/key.tf");
        assert!(facts[1].excerpt.contains("co-location alone"));
        assert!(
            facts
                .iter()
                .all(|f| !f.excerpt.contains("AAAA") && !f.symbol.contains("AAAA"))
        );
        project_investigation_facts(ReviewReadiness::Investigation, &mut facts, &route.location);
        assert!(facts.iter().all(|f| !f.excerpt.is_empty()));
        let mut plan = review_investigation_plan(
            Capability::HttpRequestHandling,
            &questions(&facts),
            &ReviewContextTruncation::default(),
            &route.location,
            None,
        );
        route_lookups(&mut plan, &facts);
        assert_eq!(plan.lookup_requests.len(), 2);
        assert_eq!(
            plan.lookup_requests[0].arguments.path.as_deref(),
            Some("downloads/key.tf")
        );
        assert_eq!(
            plan.lookup_requests[1].arguments.path.as_deref(),
            Some("signer.ts")
        );
        let index = Index::build(&source, &[], &[group(route.clone())]);
        assert!(
            index.facts(&source, &[route]).0.is_empty(),
            "unobserved keys are not signer relationships"
        );
    }

    #[test]
    fn file_content_literal_roots_reject_ambiguous_resolution() {
        for root in [
            "../files",
            "files/../private",
            "/files",
            "C:/files",
            "files\\keys",
            "$ROOT",
            "",
        ] {
            assert!(directory_root(&index_route(root)).is_none(), "{root}");
        }
        assert_eq!(
            directory_root(&index_route("./files//keys/")),
            Some("files/keys".into())
        );
        assert_eq!(directory_root(&index_route(".")), Some(String::new()));
        assert!(!in_root("files-other/key", "files"));
    }

    #[test]
    fn file_content_assignment_fallback_does_not_scan_unbounded_minified_gaps() {
        let text = format!(
            "const content = fs.readFile(path);{}yaml.load(content);",
            " ".repeat(MAX_ASSIGNMENT_BYTES + 1)
        );
        let mut parser = item(
            "reader.ts",
            &text,
            "yaml.load(content)",
            Capability::Deserialization,
        );
        captured(&mut parser, &text, "payload", "content");
        let read = item(
            "reader.ts",
            &text,
            "fs.readFile(path)",
            Capability::FilesystemRead,
        );
        let file = SourceFile {
            path: "reader.ts".into(),
            language: None,
            source: text,
        };
        assert!(!file_payload(&parser, &read, &file));
        // A bounded suffix starting within a multibyte character remains valid.
        let text = format!(
            "{}; const content = fs.readFile(path); yaml.load(content);",
            "界".repeat(800)
        );
        let mut parser = item(
            "reader.ts",
            &text,
            "yaml.load(content)",
            Capability::Deserialization,
        );
        captured(&mut parser, &text, "payload", "content");
        let read = item(
            "reader.ts",
            &text,
            "fs.readFile(path)",
            Capability::FilesystemRead,
        );
        let file = SourceFile {
            path: "reader.ts".into(),
            language: None,
            source: text,
        };
        assert!(file_payload(&parser, &read, &file));
    }

    #[test]
    fn file_content_search_caps_report_partial_instead_of_absence() {
        let key = pem('A');
        let signer = format!("{key}\njwt.sign(value, key)");
        let mut source = sources(&[("signer.ts", &signer)]);
        for n in 0..=MAX_FILES {
            let path = format!("downloads/{n:04}.tf");
            source.files.insert(
                path.clone(),
                SourceFile {
                    path,
                    language: None,
                    source: if n == MAX_FILES {
                        key.clone()
                    } else {
                        "empty".into()
                    },
                },
            );
        }
        let route = index_route("downloads");
        let all = vec![item(
            "signer.ts",
            &signer,
            "jwt.sign",
            Capability::TokenGeneration,
        )];
        let index = Index::build(&source, &all, &[group(route.clone())]);
        let (facts, cut) = index.facts(&source, &[route]);
        assert!(cut);
        assert_eq!(facts.len(), 1);
        assert!(facts[0].excerpt.contains("Missing matches do not prove"));
        assert!(index.copies["downloads"].is_empty());
    }

    #[test]
    fn file_content_writer_leads_are_bounded_and_do_not_enrich_unrelated_rules() {
        let text = "yaml.load(fs.readFile(path))";
        let mut parser = item("reader.ts", text, text, Capability::Deserialization);
        captured(&mut parser, text, "payload", "fs.readFile(path)");
        let mut source = sources(&[("reader.ts", text)]);
        let mut all = vec![item(
            "reader.ts",
            text,
            "fs.readFile(path)",
            Capability::FilesystemRead,
        )];
        for n in 0..3 {
            let path = format!("writer{n}.ts");
            source.files.insert(
                path.clone(),
                SourceFile {
                    path: path.clone(),
                    language: None,
                    source: "write(entry.path)".into(),
                },
            );
            let mut writer = item(
                &path,
                "write(entry.path)",
                "write(entry.path)",
                Capability::FilesystemWrite,
            );
            writer.rule_id = "typescript-archive-raw-path-write".into();
            all.push(writer);
        }
        let index = Index::build(&source, &all, &[group(parser.clone())]);
        let (facts, cut) = index.facts(&source, &[parser.clone()]);
        assert!(cut);
        assert_eq!(
            facts
                .iter()
                .filter(|f| f.role == "possible_file_content_writer_context")
                .count(),
            MAX_WRITERS
        );
        parser.capability = Capability::DatabaseQuery;
        assert!(index.facts(&source, &[parser]).0.is_empty());
    }
}
