//! ZIP entry metadata flowing into allocation and filesystem effects.
use super::*;
use rust_allocation::{method, receiver_type};
use rust_module_bindings::{Located, Project};
use rust_parser_provenance::{arguments, enclosing_function, literal, named, peel, unique};
use rust_receiver_types::local_binding;
use rust_shared_state::AstNode as N;

const MAX_SMALL_TARGET_BYTES: usize = 64 * 1024;
type ReviewedExtents = BTreeSet<(String, usize)>;

fn expression<'a>(node: &N<'a>) -> Option<N<'a>> {
    if node.kind().as_ref() == "expression_statement" {
        named(node).next()
    } else {
        Some(node.clone())
    }
}

fn previous<'a>(node: &N<'a>) -> Option<N<'a>> {
    let block = node.parent().filter(|n| n.kind().as_ref() == "block")?;
    named(&block)
        .take_while(|n| n.range().end <= node.range().start)
        .last()
}

fn declared_size<'a>(value: N<'a>, function: &N<'a>, depth: usize) -> Option<(N<'a>, N<'a>)> {
    if depth == 0 {
        return None;
    }
    if value.kind().as_ref() == "parenthesized_expression" {
        return declared_size(unique(named(&value))?, function, depth - 1);
    }
    if value.kind().as_ref() == "identifier" {
        let binding = local_binding(&value, function)?;
        return declared_size(binding.field("value")?, function, depth - 1);
    }
    let (entry, name) = method(&value)?;
    (name == "size" && arguments(&value)?.is_empty()).then_some((value, entry))
}

fn same_entry<'a>(left: &N<'a>, right: &N<'a>, function: &N<'a>) -> bool {
    local_binding(left, function)
        .zip(local_binding(right, function))
        .is_some_and(|(a, b)| a.range() == b.range())
}

fn symlink_branch<'a>(binding: &N<'a>, entry: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let body = binding.parent()?;
    let branch = body
        .parent()
        .filter(|n| n.kind().as_ref() == "if_expression")?;
    if branch.field("consequence")?.range() != body.range() {
        return None;
    }
    let test = branch.field("condition")?;
    let (other, name) = method(&test)?;
    (name == "is_symlink" && arguments(&test)?.is_empty() && same_entry(&other, entry, function))
        .then_some(test)
}

fn read_target<'a>(binding: &N<'a>, entry: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    let next = named(&binding.parent()?).find(|n| n.range().start >= binding.range().end)?;
    let read = peel(expression(&next)?)?;
    let (receiver, name) = method(&read)?;
    let arg = peel(unique(arguments(&read)?.into_iter())?)?;
    (name == "read_to_end"
        && same_entry(&receiver, entry, function)
        && local_binding(&arg, function)?.range() == binding.range())
    .then_some(read)
}

fn crate_manifest<'a>(
    sources: &'a RepositorySources,
    project: &Project<'a>,
    place: &Located<'a>,
) -> Option<Capture> {
    let root = project.crate_scope(place)?;
    let capture = project
        .support(&root)
        .into_iter()
        .find(|c| c.location.path.rsplit('/').next() == Some("Cargo.toml"))?;
    let manifest = sources.files.get(&capture.location.path)?;
    let cargo = toml_edit::Document::parse(manifest.source.as_str()).ok()?;
    (cargo.get("package")?.get("name")?.as_str()? == "zip").then_some(capture)
}

fn indexed_entry<'a>(root: &N<'a>, function: &N<'a>, entry: &N<'a>, in_zip: bool) -> Option<N<'a>> {
    let producer = peel(local_binding(entry, function)?.field("value")?)?;
    let (archive, name) = method(&producer)?;
    if !matches!(name.as_str(), "by_index" | "by_name") || arguments(&producer)?.len() != 1 {
        return None;
    }
    if archive.text() == "self" && in_zip {
        let implementation = function.parent()?.parent()?;
        if implementation.kind().as_ref() != "impl_item" || implementation.field("trait").is_some()
        {
            return None;
        }
        let ty = implementation.field("type")?;
        let ty = ty.field("type").unwrap_or(ty);
        let owner = rust_raw_memory::canonical(root, &ty, &ty.text())?;
        // A grouped `pub use` is a declaration in the local module too.
        // Keep this fallback scoped to the verified SDK crate.
        let owner = if owner == ty.text() && !owner.contains("::") {
            let scope = rust_parser_provenance::scope(function)?;
            let mut imports = Vec::new();
            for item in named(&scope).filter(|n| n.kind().as_ref() == "use_declaration") {
                rust_shared_state::imports(&item, "", true, &mut imports);
            }
            unique(imports.into_iter().filter(|(name, _, _)| name == &owner))?.1
        } else {
            owner
        };
        return matches!(
            owner.as_str(),
            "crate::ZipArchive"
                | "crate::read::ZipArchive"
                | "crate::read::zip_archive::ZipArchive"
                | "zip_archive::ZipArchive"
                | "self::zip_archive::ZipArchive"
        )
        .then_some(producer);
    }
    matches!(
        receiver_type(root, &archive, function, 0).as_deref(),
        Some("zip::ZipArchive" | "zip::read::ZipArchive")
    )
    .then_some(producer)
}

fn constant<'a>(
    project: &Project<'a>,
    place: &Located<'a>,
    root: &N<'a>,
    limit: &N<'a>,
) -> Option<usize> {
    if let Some(value) = literal(limit) {
        return Some(value);
    }
    let name = rust_raw_memory::canonical(root, limit, &limit.text())?;
    let (scope, name) = if let Some(path) = name.strip_prefix("crate::") {
        let mut modules = path.split("::").collect::<Vec<_>>();
        let name = modules.pop()?;
        let mut scope = project.crate_scope(place)?;
        for module in modules {
            let item = unique(named(&scope.node).filter(|n| {
                n.kind().as_ref() == "mod_item"
                    && n.field("name").is_some_and(|n| n.text() == module)
                    && project.selected(&scope.with_node(n.clone()))
            }))?;
            scope = project.child_scope(&scope, &item)?;
        }
        (scope, name)
    } else {
        if name.contains("::") {
            return None;
        }
        (project.current_scope(place)?, name.as_str())
    };
    // A locally bound name must not inherit a module constant's value.
    if let Some(function) = enclosing_function(limit)
        && local_binding(limit, &function).is_some()
    {
        return None;
    }
    if limit.kind().as_ref() == "identifier"
        && limit
            .ancestors()
            .filter(|n| n.kind().as_ref() == "block")
            .any(|block| {
                named(&block).any(|item| {
                    item.kind().as_ref() == "const_item"
                        && item.field("name").is_some_and(|n| n.text() == limit.text())
                })
            })
    {
        return None;
    }
    let item = unique(named(&scope.node).filter(|n| {
        n.kind().as_ref() == "const_item"
            && n.field("name").is_some_and(|n| n.text() == name)
            && project.selected(&scope.with_node(n.clone()))
    }))?;
    literal(&item.field("value")?)
}

fn small_cap<'a>(
    project: &Project<'a>,
    place: &Located<'a>,
    root: &N<'a>,
    binding: &N<'a>,
    function: &N<'a>,
    size: &N<'a>,
) -> Option<()> {
    let guard = expression(&previous(binding)?)?;
    if guard.kind().as_ref() != "if_expression"
        || guard.field("alternative").is_some()
        || !project.selected(&place.with_node(guard.clone()))
    {
        return None;
    }
    let consequence = guard.field("consequence")?;
    if expression(&unique(named(&consequence))?)?.kind().as_ref() != "return_expression" {
        return None;
    }
    let condition = guard.field("condition")?;
    if condition.kind().as_ref() != "binary_expression"
        || !matches!(condition.field("operator")?.text().as_ref(), ">" | ">=")
    {
        return None;
    }
    let checked = condition.field("left")?;
    // Require the declared value itself, before any narrowing cast.
    if checked.kind().as_ref() != "identifier"
        || declared_size(checked, function, 6)?.0.range() != size.range()
    {
        return None;
    }
    (constant(project, place, root, &condition.field("right")?)? <= MAX_SMALL_TARGET_BYTES)
        .then_some(())
}

fn visitor_root<'a>(root: &N<'a>, implementation: &N<'a>, base: &N<'a>) -> Option<()> {
    if base.kind().as_ref() != "field_expression" || base.field("value")?.text() != "self" {
        return None;
    }
    let index = base.field("field")?.text().parse::<usize>().ok()?;
    let owner = implementation.field("type")?;
    if owner.kind().as_ref() != "type_identifier" {
        return None;
    }
    let scope = implementation.parent()?;
    let declaration = unique(named(&scope).filter(|n| {
        n.field("name")
            .is_some_and(|name| name.text() == owner.text())
    }))?;
    if declaration.kind().as_ref() != "struct_item" {
        return None;
    }
    let fields = declaration.field("body")?;
    if fields.kind().as_ref() != "ordered_field_declaration_list" {
        return None;
    }
    let ty = named(&fields).nth(index)?;
    matches!(
        rust_raw_memory::canonical(root, &ty, &ty.text()).as_deref(),
        Some("std::path::PathBuf")
    )
    .then_some(())
}

fn metadata_permissions<'a>(
    root: &N<'a>,
    call: &N<'a>,
    function: &N<'a>,
    in_zip: bool,
) -> Option<[(&'static str, N<'a>); 4]> {
    let [destination, permission] = arguments(call)?.try_into().ok()?;
    if rust_raw_memory::api(root, &permission).as_deref() != Some("std::fs::Permissions::from_mode")
    {
        return None;
    }
    let mode = unique(arguments(&permission)?.into_iter())?;
    let statement = call
        .parent()
        .filter(|n| n.kind().as_ref() == "try_expression")?
        .parent()?;
    let body = statement.parent()?;
    let branch = body
        .parent()
        .filter(|n| n.kind().as_ref() == "if_expression")?;
    if branch.field("alternative").is_some()
        || branch.field("consequence")?.range() != body.range()
        || unique(named(&body))?.range() != statement.range()
    {
        return None;
    }
    let condition = branch.field("condition")?;
    let pattern = condition.field("pattern")?;
    let variant = pattern.field("type")?;
    if variant.text() != "Some"
        || mode.kind().as_ref() != "identifier"
        || unique(named(&pattern).filter(|n| n.range() != variant.range()))?.text() != mode.text()
    {
        return None;
    }
    let mode_source = condition.field("value")?;
    let (metadata, name) = method(&mode_source)?;
    if name != "unix_mode" || !arguments(&mode_source)?.is_empty() {
        return None;
    }
    let owner = receiver_type(root, &metadata, function, 0)?;
    let external = owner == "zip::unstable::stream::ZipStreamFileMetadata";
    if !external && !(in_zip && owner == "self::ZipStreamFileMetadata") {
        return None;
    }
    let implementation = function.parent()?.parent()?;
    let trait_name = implementation.field("trait")?;
    let trait_name = rust_raw_memory::canonical(root, &trait_name, &trait_name.text())?;
    if function.field("name")?.text() != "visit_additional_metadata"
        || !(trait_name == "zip::unstable::stream::ZipStreamVisitor"
            || in_zip && trait_name == "self::ZipStreamVisitor")
    {
        return None;
    }
    let branch_statement = if branch.parent()?.kind().as_ref() == "expression_statement" {
        branch.parent()?
    } else {
        branch
    };
    let path_binding = previous(&branch_statement)?;
    if local_binding(&peel(destination)?, function)?.range() != path_binding.range() {
        return None;
    }
    let join = path_binding.field("value")?;
    let (base, name) = method(&join)?;
    if name != "join" {
        return None;
    }
    visitor_root(root, &implementation, &base)?;
    let name_arg = unique(arguments(&join)?.into_iter())?;
    let name_binding = previous(&path_binding)?;
    if local_binding(&name_arg, function)?.range() != name_binding.range() {
        return None;
    }
    let unwrap = name_binding.field("value")?;
    if unwrap.kind().as_ref() != "try_expression" {
        return None;
    }
    let (enclosed, name) = method(&peel(unwrap)?)?;
    let (other, enclosed_method) = method(&enclosed)?;
    if !matches!(name.as_str(), "ok_or" | "ok_or_else")
        || enclosed_method != "enclosed_name"
        || !arguments(&enclosed)?.is_empty()
        || !same_entry(&metadata, &other, function)
    {
        return None;
    }
    // Limit this marker to a direct lexical rebuild. A guard on the selected
    // output or its resolved parent needs its own evidence before admission.
    if named(&name_binding.parent()?)
        .take_while(|n| n.range().start < name_binding.range().start)
        .any(|n| n.kind().as_ref() != "use_declaration")
    {
        return None;
    }
    Some([
        ("permission_sink", call.clone()),
        ("metadata_name", enclosed),
        ("lexical_destination", join),
        ("metadata_mode", mode_source),
    ])
}

fn emit<'a>(
    file: &SourceFile,
    rule: &str,
    capability: Capability,
    cwe: &str,
    tag: &str,
    function: &N<'a>,
    facts: impl IntoIterator<Item = (&'static str, N<'a>)>,
    manifest: Option<Capture>,
    scope: Option<&mehscan_core::ImpactScanScope>,
) -> Option<ObservationGroup> {
    let mut facts = facts.into_iter();
    let (role, anchor) = facts.next()?;
    let capture = rust_dependencies::capture(file, &anchor);
    let location = capture.location.clone();
    let mut captures = facts
        .map(|(role, n)| (role.into(), rust_dependencies::capture(file, &n)))
        .collect::<BTreeMap<_, _>>();
    captures.insert(role.into(), capture);
    if let Some(manifest) = manifest {
        captures.insert("archive_package".into(), manifest);
    }
    if scope.is_some_and(|s| {
        s.result_policy == "changed_locations"
            && !captures.values().any(|capture| {
                crate::impact::location_is_changed(&capture.location, &s.changed_files)
            })
    }) {
        return None;
    }
    let id = review_admission_marker_id(&file.path, rule, anchor.range().start, anchor.range().end);
    let symbol = function.field("name")?.text().into_owned();
    Some(ObservationGroup {
        path: file.path.clone(),
        symbol: symbol.clone(),
        anchor_evidence_ids: vec![id.clone()],
        priority: 1,
        review_material: is_review_material_path(&file.path),
        evidence: vec![Evidence {
            id,
            rule_id: rule.into(),
            kind: EvidenceKind::SensitiveOperation,
            capability,
            location,
            enclosing_symbol: Some(symbol),
            captures,
            cwe_candidates: vec![cwe.into()],
            tags: vec!["review-admission-marker".into(), tag.into()],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "bounded ZIP entry relationship".into(),
                rule_version: 1,
            },
            context: EvidenceContext::default(),
            symbol_resolution: None,
            related_evidence: vec![],
        }],
    })
}

pub(super) fn groups<'a>(
    sources: &'a RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &'a rust_configuration::Selection,
    parsed: &'a rust_dependencies::RustSources,
) -> (Vec<ObservationGroup>, ReviewedExtents) {
    let mut groups = Vec::new();
    let mut handled = BTreeSet::new();
    let project = std::cell::OnceCell::new();
    for file in sources.files.values().filter(|f| {
        f.language == Some(Language::Rust)
            && (f.source.contains("is_symlink") && f.source.contains("with_capacity")
                || f.source.contains("enclosed_name") && f.source.contains("set_permissions"))
    }) {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        for operation in root.dfs().filter(|n| {
            n.kind().as_ref() == "call_expression" && !selection.excluded(&file.path, n.range())
        }) {
            let api = rust_raw_memory::api(&root, &operation);
            if !matches!(
                api.as_deref(),
                Some(
                    "std::vec::Vec::with_capacity"
                        | "alloc::vec::Vec::with_capacity"
                        | "std::fs::set_permissions"
                )
            ) {
                continue;
            }
            let Some(function) = enclosing_function(&operation) else {
                continue;
            };
            if function.range().len() > 32768
                || function.dfs().any(|n| n.is_error() || n.is_missing())
                || !rust_buffer_initialization::runtime_path(&operation, &function)
            {
                continue;
            }
            if api.as_deref() == Some("std::fs::set_permissions") {
                let project = project.get_or_init(|| Project::build(sources, parsed, selection));
                let place = project.locate(file, operation.clone());
                let manifest = crate_manifest(sources, project, &place);
                if let Some(facts) =
                    metadata_permissions(&root, &operation, &function, manifest.is_some())
                {
                    groups.extend(emit(
                        file,
                        "rust-zip-stream-metadata-permissions-review",
                        Capability::RustArchiveExtractionReview,
                        "CWE-59",
                        "zip-stream-metadata-path",
                        &function,
                        facts,
                        manifest,
                        scope,
                    ));
                }
                continue;
            }
            let Some(binding) = operation
                .parent()
                .filter(|p| p.kind().as_ref() == "let_declaration")
            else {
                continue;
            };
            let Some(extent) = arguments(&operation)
                .and_then(|args| unique(args.into_iter()))
                .and_then(|arg| {
                    if arg.kind().as_ref() == "type_cast_expression"
                        && arg.field("type").is_some_and(|ty| ty.text() == "usize")
                    {
                        arg.field("value")
                    } else {
                        Some(arg)
                    }
                })
            else {
                continue;
            };
            let Some((size, entry)) = declared_size(extent, &function, 6) else {
                continue;
            };
            let Some(test) = symlink_branch(&binding, &entry, &function) else {
                continue;
            };
            let Some(read) = read_target(&binding, &entry, &function) else {
                continue;
            };
            let project = project.get_or_init(|| Project::build(sources, parsed, selection));
            let place = project.locate(file, operation.clone());
            let manifest = crate_manifest(sources, project, &place);
            let indexed = indexed_entry(&root, &function, &entry, manifest.is_some());
            let typed = receiver_type(&root, &entry, &function, 0).is_some_and(|ty| {
                matches!(ty.as_str(), "zip::read::ZipFile" | "zip::ZipFile")
                    || manifest.is_some()
                        && matches!(
                            ty.as_str(),
                            "crate::read::ZipFile" | "crate::read::zipfile::ZipFile"
                        )
            });
            if indexed.is_none() && !typed {
                continue;
            }
            if small_cap(project, &place, &root, &binding, &function, &size).is_some() {
                handled.insert((file.path.clone(), operation.range().start));
                continue;
            }
            // A typed visitor parameter does not establish that the stream
            // reader can produce a symlink. Require the indexed producer.
            let Some(indexed) = indexed else { continue };
            handled.insert((file.path.clone(), operation.range().start));
            let facts = [
                ("allocation_operation", operation),
                ("declared_size", size),
                ("archive_entry", indexed),
                ("symlink_branch", test),
                ("entry_payload_read", read),
            ];
            groups.extend(emit(
                file,
                "rust-zip-symlink-target-allocation-review",
                Capability::RustAllocationReview,
                "CWE-789",
                "zip-declared-entry-size",
                &function,
                facts,
                manifest,
                scope,
            ));
        }
    }
    (groups, handled)
}
