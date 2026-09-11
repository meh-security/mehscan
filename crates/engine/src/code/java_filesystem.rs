use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SymbolConfidence, SymbolResolution, SymbolResolutionMethod,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::{enclosing_symbol, enclosing_type_start, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;
use super::symbols::parameter_shadows_name;

const ENGINE: &str = "mehscan java-filesystem-archive-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_filesystem_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "java-filesystem-read"
                | "java-filesystem-write"
                | "java-path-canonicalization"
                | "java-path-containment-check"
        )
    });
    let imports = imports(root);
    let declarations = declared_types(root);
    add_filesystem_access(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_path_controls(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_archive_policy(
        path,
        root,
        &imports,
        &declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_filesystem_access<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let files = imported_exact(imports, declarations, "java.nio.file.Files", "Files");
    let multipart = imported_exact(
        imports,
        declarations,
        "org.springframework.web.multipart.MultipartFile",
        "MultipartFile",
    );
    let file_resource = imported_exact(
        imports,
        declarations,
        "org.springframework.core.io.FileSystemResource",
        "FileSystemResource",
    );

    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|name| name.text().into_owned())
        else {
            continue;
        };
        let args = arguments(&invocation);
        let object = invocation.field("object");
        let exact_files_call = files
            && object.as_ref().is_some_and(|object| {
                object.text().trim() == "Files"
                    && !parameter_shadows_name(&invocation, "Files", Language::Java)
            })
            || object.is_none()
                && (imports.contains(&format!("java.nio.file.Files.{operation}"))
                    || imports.contains("java.nio.file.Files.*"));

        if exact_files_call
            && files_read_methods().contains(&operation.as_str())
            && let Some(file_path) = args.first()
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::FilesystemRead,
                "java-filesystem-read",
                &["CWE-22"],
                &["filesystem", "path", "java-nio", operation.as_str()],
                &[("path", file_path)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if exact_files_call
            && files_write_methods().contains(&operation.as_str())
            && let Some(file_path) = args.first()
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::FilesystemWrite,
                "java-filesystem-write",
                &["CWE-22"],
                &["filesystem", "path", "java-nio", operation.as_str()],
                &[("path", file_path)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if exact_files_call
            && matches!(operation.as_str(), "copy" | "move")
            && args.len() >= 2
            && path_expression(&invocation, &args[1])
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::FilesystemWrite,
                "java-filesystem-write",
                &["CWE-22"],
                &["filesystem", "path", "java-nio", operation.as_str()],
                &[("path", &args[1]), ("content", &args[0])],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if multipart
            && operation == "transferTo"
            && object
                .as_ref()
                .is_some_and(|object| receiver_is_at(&invocation, object, "MultipartFile"))
            && let (Some(object), Some(destination)) = (object.as_ref(), args.first())
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::FilesystemWrite,
                "java-spring-multipart-transfer-to-filesystem",
                &["CWE-22", "CWE-434"],
                &["filesystem", "upload", "spring-multipart", "destination"],
                &[("path", destination), ("content", object)],
                comments,
                conditional,
                literals,
                evidence,
            );
            push(
                path,
                &invocation,
                EvidenceKind::Sink,
                Capability::FileUpload,
                "java-spring-multipart-file-storage",
                &["CWE-434"],
                &["filesystem", "upload", "spring-multipart", "storage"],
                &[("content", object), ("destination", destination)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for creation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "object_creation_expression")
    {
        let Some(kind) = creation.field("type") else {
            continue;
        };
        let kind_text = kind.text();
        let short = short_type(kind_text.as_ref());
        let (capability, rule_id, canonical) = match short {
            "FileInputStream" => (
                Capability::FilesystemRead,
                "java-file-stream-read",
                "java.io.FileInputStream",
            ),
            "FileReader" => (
                Capability::FilesystemRead,
                "java-file-reader-read",
                "java.io.FileReader",
            ),
            "RandomAccessFile" => (
                Capability::FilesystemRead,
                "java-random-access-file",
                "java.io.RandomAccessFile",
            ),
            "FileOutputStream" => (
                Capability::FilesystemWrite,
                "java-file-stream-write",
                "java.io.FileOutputStream",
            ),
            "FileWriter" => (
                Capability::FilesystemWrite,
                "java-file-writer-write",
                "java.io.FileWriter",
            ),
            "FileSystemResource" => (
                Capability::FilesystemRead,
                "java-spring-filesystem-resource",
                "org.springframework.core.io.FileSystemResource",
            ),
            _ => continue,
        };
        if short == "FileSystemResource" && !file_resource
            || short != "FileSystemResource"
                && !imported_exact(imports, declarations, canonical, short)
        {
            continue;
        }
        let Some(file_path) = creation
            .field("arguments")
            .and_then(|args| args.children().find(|child| child.is_named()))
        else {
            continue;
        };
        push(
            path,
            &creation,
            EvidenceKind::Sink,
            capability,
            rule_id,
            &["CWE-22"],
            &["filesystem", "path", short],
            &[("path", &file_path)],
            comments,
            conditional,
            literals,
            evidence,
        );
        if short == "RandomAccessFile"
            && creation.field("arguments").is_some_and(|args| {
                args.children()
                    .filter(|child| child.is_named())
                    .nth(1)
                    .is_some_and(|mode| mode.text().contains('w'))
            })
        {
            push(
                path,
                &creation,
                EvidenceKind::Sink,
                Capability::FilesystemWrite,
                "java-random-access-file-write",
                &["CWE-22"],
                &["filesystem", "path", "RandomAccessFile", "write-mode"],
                &[("path", &file_path)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_path_controls<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let path_type = imported_exact(imports, declarations, "java.nio.file.Path", "Path");
    let paths = imported_exact(imports, declarations, "java.nio.file.Paths", "Paths");
    let file = imported_exact(imports, declarations, "java.io.File", "File");
    let files = imported_exact(imports, declarations, "java.nio.file.Files", "Files");

    for invocation in invocations(root) {
        let Some(operation) = invocation
            .field("name")
            .map(|name| name.text().into_owned())
        else {
            continue;
        };
        let object = invocation.field("object");
        if matches!(operation.as_str(), "normalize" | "toRealPath")
            && let Some(object) = object.as_ref()
            && (path_type && receiver_is_at(&invocation, object, "Path")
                || path_creator(object, paths, path_type))
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sanitizer,
                Capability::PathCanonicalization,
                "java-path-canonicalization",
                &["CWE-22"],
                &[
                    "filesystem",
                    "path",
                    if operation == "toRealPath" {
                        "real-path"
                    } else {
                        "lexical-normalization"
                    },
                ],
                &[("value", object)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if file
            && matches!(operation.as_str(), "getCanonicalPath" | "getCanonicalFile")
            && let Some(object) = object.as_ref()
            && receiver_is_at(&invocation, object, "File")
        {
            push(
                path,
                &invocation,
                EvidenceKind::Sanitizer,
                Capability::PathCanonicalization,
                "java-path-canonicalization",
                &["CWE-22"],
                &["filesystem", "path", "canonical-file"],
                &[("value", object)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if operation == "startsWith"
            && let (Some(candidate), Some(base)) = (object.as_ref(), arguments(&invocation).first())
            && normalized_path_expression(&invocation, candidate, paths, path_type)
            && normalized_path_expression(&invocation, base, paths, path_type)
        {
            push(
                path,
                &invocation,
                EvidenceKind::Validation,
                Capability::PathContainmentCheck,
                "java-path-containment-check",
                &["CWE-22"],
                &[
                    "filesystem",
                    "path",
                    "containment",
                    if candidate.text().contains("toRealPath") && base.text().contains("toRealPath")
                    {
                        "real-path"
                    } else {
                        "lexical"
                    },
                ],
                &[("path", candidate), ("base", base)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        if files
            && operation == "isSymbolicLink"
            && object
                .as_ref()
                .is_some_and(|object| object.text().trim() == "Files")
            && let Some(candidate) = arguments(&invocation).first()
        {
            push(
                path,
                &invocation,
                EvidenceKind::Validation,
                Capability::PathContainmentCheck,
                "java-symbolic-link-check-control",
                &["CWE-22"],
                &["filesystem", "path", "symbolic-link"],
                &[("path", candidate)],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    for invocation in invocations(root) {
        if invocation.text().contains("LinkOption.NOFOLLOW_LINKS") {
            push_without_capture(
                path,
                &invocation,
                EvidenceKind::Validation,
                Capability::PathContainmentCheck,
                "java-no-follow-links-control",
                &["CWE-22"],
                &["filesystem", "path", "no-follow-links"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if invocation
            .text()
            .contains("StandardCopyOption.REPLACE_EXISTING")
            || invocation
                .text()
                .contains("StandardOpenOption.TRUNCATE_EXISTING")
        {
            push_without_capture(
                path,
                &invocation,
                EvidenceKind::SecurityConfiguration,
                Capability::FilesystemWrite,
                "java-filesystem-overwrite-enabled",
                &[],
                &["filesystem", "overwrite", "explicit"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_archive_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let archive_entries = [
        (
            imported_exact(imports, declarations, "java.util.zip.ZipEntry", "ZipEntry"),
            "ZipEntry",
            "java-zip-entry-name",
            "zip",
        ),
        (
            imported_exact(imports, declarations, "java.util.jar.JarEntry", "JarEntry"),
            "JarEntry",
            "java-jar-entry-name",
            "jar",
        ),
        (
            imported_exact(
                imports,
                declarations,
                "org.apache.commons.compress.archivers.zip.ZipArchiveEntry",
                "ZipArchiveEntry",
            ),
            "ZipArchiveEntry",
            "java-commons-zip-entry-name",
            "commons-zip",
        ),
        (
            imported_exact(
                imports,
                declarations,
                "org.apache.commons.compress.archivers.tar.TarArchiveEntry",
                "TarArchiveEntry",
            ),
            "TarArchiveEntry",
            "java-tar-entry-name",
            "tar",
        ),
    ];
    if !archive_entries.iter().any(|(available, ..)| *available) {
        return;
    }
    for invocation in invocations(root) {
        if invocation
            .field("name")
            .is_none_or(|name| name.text().as_ref() != "getName")
        {
            continue;
        }
        let Some(entry) = invocation.field("object") else {
            continue;
        };
        let Some((_, _, rule_id, family)) = archive_entries
            .iter()
            .find(|(available, kind, ..)| *available && receiver_is_at(&invocation, &entry, kind))
        else {
            continue;
        };
        push(
            path,
            &invocation,
            EvidenceKind::Source,
            Capability::ArchiveEntryPath,
            rule_id,
            &["CWE-22"],
            &["archive", family, "entry-path", "attacker-controlled"],
            &[("path", &invocation)],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn files_read_methods() -> &'static [&'static str] {
    &[
        "readString",
        "readAllBytes",
        "newBufferedReader",
        "newInputStream",
        "lines",
        "list",
        "walk",
    ]
}

fn files_write_methods() -> &'static [&'static str] {
    &[
        "write",
        "writeString",
        "newBufferedWriter",
        "newOutputStream",
        "delete",
        "deleteIfExists",
        "createDirectory",
        "createDirectories",
    ]
}

fn path_expression(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    node: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    receiver_is_at(use_site, node, "Path")
        || compact(node.text().as_ref()).contains("Paths.get(")
        || compact(node.text().as_ref()).contains("Path.of(")
        || node.text().contains(".resolve(")
}

fn path_creator(node: &Node<'_, StrDoc<SupportLang>>, paths: bool, path_type: bool) -> bool {
    let text = compact(node.text().as_ref());
    paths && text.starts_with("Paths.get(") || path_type && text.starts_with("Path.of(")
}

fn normalized_path_expression(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    node: &Node<'_, StrDoc<SupportLang>>,
    paths: bool,
    path_type: bool,
) -> bool {
    let text = compact(node.text().as_ref());
    let direct = text.contains(".normalize()")
        && (paths && text.contains("Paths.get(")
            || path_type && (text.contains("Path.of(") || text.contains(".toAbsolutePath()")))
        || text.contains(".toRealPath(");
    direct
        || receiver_is_at(use_site, node, "Path")
            && initializer_before(use_site, node.text().trim()).is_some_and(|initializer| {
                let text = compact(initializer.text().as_ref());
                text.contains(".normalize()") || text.contains(".toRealPath(")
            })
}

fn initializer_before<'tree>(
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    name: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let scope = use_site.ancestors().find(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "constructor_declaration"
        )
    })?;
    scope
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node.range().start < use_site.range().start
                && node
                    .field("name")
                    .is_some_and(|candidate| candidate.text().trim() == name)
        })
        .filter_map(|node| node.field("value"))
        .last()
}

fn receiver_is_at(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    expected: &str,
) -> bool {
    let name_text = receiver.text();
    let name = name_text.trim();
    let Some(scope) = use_site.ancestors().find(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "constructor_declaration"
        )
    }) else {
        return false;
    };
    let mut found = None;
    for node in scope
        .dfs()
        .filter(|node| node.range().start <= use_site.range().start)
    {
        if matches!(node.kind().as_ref(), "parameter" | "formal_parameter")
            && node
                .field("name")
                .is_some_and(|candidate| candidate.text().trim() == name)
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
        if node.kind().as_ref() == "local_variable_declaration"
            && lexical_declaration_visible_at(&node, use_site)
            && node.children().any(|child| {
                child.kind().as_ref() == "variable_declarator"
                    && child
                        .field("name")
                        .is_some_and(|candidate| candidate.text().trim() == name)
            })
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
        if node.kind().as_ref() == "enhanced_for_statement"
            && lexical_declaration_visible_at(&node, use_site)
            && node
                .field("name")
                .is_some_and(|candidate| candidate.text().trim() == name)
            && let Some(kind) = node.field("type")
        {
            found = Some(kind.text().into_owned());
        }
    }
    if found.is_some_and(|kind| short_type(&kind) == expected) {
        return true;
    }
    let use_owner = enclosing_type_start(use_site);
    use_site.ancestors().last().is_some_and(|root| {
        root.dfs().any(|node| {
            node.kind().as_ref() == "field_declaration"
                && enclosing_type_start(&node) == use_owner
                && node
                    .field("type")
                    .is_some_and(|kind| short_type(kind.text().as_ref()) == expected)
                && node.children().any(|child| {
                    child.kind().as_ref() == "variable_declarator"
                        && child
                            .field("name")
                            .is_some_and(|candidate| candidate.text().trim() == name)
                })
        })
    })
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
}

fn arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn imports(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .map(|import| {
            import
                .text()
                .trim()
                .trim_start_matches("import ")
                .trim_start_matches("static ")
                .trim_end_matches(';')
                .to_string()
        })
        .collect()
}

fn declared_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
                    | "annotation_type_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .map(|name| name.text().into_owned())
        .collect()
}

fn imported_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonical: &str,
    short: &str,
) -> bool {
    let namespace = canonical
        .rsplit_once('.')
        .map(|(namespace, _)| namespace)
        .unwrap_or_default();
    !declarations.contains(short)
        && (imports.contains(canonical) || imports.contains(&format!("{namespace}.*")))
}

fn short_type(kind: &str) -> &str {
    kind.trim()
        .rsplit('.')
        .next()
        .unwrap_or(kind.trim())
        .split('<')
        .next()
        .unwrap_or(kind.trim())
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: &[(&str, &Node<'tree, StrDoc<SupportLang>>)],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut literal_values = BTreeMap::new();
    let captures = captures
        .iter()
        .map(|(role, capture)| {
            literal_values.insert((*role).to_string(), literals.evaluate(capture));
            (
                (*role).to_string(),
                Capture {
                    text: capture.text().into_owned(),
                    location: location(path, capture),
                },
            )
        })
        .collect();
    push_evidence(
        path,
        node,
        kind,
        capability,
        rule_id,
        cwes,
        tags,
        captures,
        literal_values,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_without_capture<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        node,
        kind,
        capability,
        rule_id,
        cwes,
        tags,
        BTreeMap::new(),
        BTreeMap::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    cwes: &[&str],
    tags: &[&str],
    captures: BTreeMap<String, Capture>,
    literal_values: BTreeMap<String, mehscan_core::LiteralEvaluation>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
    let symbol_resolution = files_symbol_resolution(node, rule_id);
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            literals: literal_values,
            ..EvidenceContext::default()
        },
        symbol_resolution,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn files_symbol_resolution(
    node: &Node<'_, StrDoc<SupportLang>>,
    rule_id: &str,
) -> Option<SymbolResolution> {
    if !matches!(rule_id, "java-filesystem-read" | "java-filesystem-write")
        || node.kind().as_ref() != "method_invocation"
    {
        return None;
    }
    let operation = node.field("name")?.text().into_owned();
    let object = node.field("object");
    let (observed, method) = if let Some(object) = object {
        if object.text().trim() != "Files" {
            return None;
        }
        (
            format!("Files.{operation}"),
            SymbolResolutionMethod::ImportedNamespace,
        )
    } else {
        (operation.clone(), SymbolResolutionMethod::StaticImport)
    };
    Some(SymbolResolution {
        canonical: format!("java.nio.file.Files.{operation}"),
        observed,
        method,
        confidence: SymbolConfidence::High,
    })
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
