use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, ResourcePolicyContext, ResourcePolicyState,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::csharp_handoff::{CsharpHandoffCatalogBuilder, CsharpHandoffProjectContext};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp-ef-model-policy 1";

#[derive(Clone, Debug, Default)]
struct ModelCatalog {
    context_sets: BTreeMap<String, BTreeMap<String, String>>,
    sensitive_fields: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct CsharpModelProjectContext {
    catalog: ModelCatalog,
    handoff: CsharpHandoffProjectContext,
}

impl CsharpModelProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut context = Self::default();
        let mut handoff = CsharpHandoffCatalogBuilder::default();
        for (path, language, source) in sources {
            if language != Language::Csharp {
                continue;
            }
            let Ok(document) = StrDoc::try_new(source, SupportLang::CSharp) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            let root = ast.root();
            if root.dfs().any(|node| node.is_error() || node.is_missing()) {
                continue;
            }
            merge_catalog(&mut context.catalog, build_catalog(&root));
            handoff.add_file(path, &root);
        }
        context.handoff = handoff.finish();
        context
    }

    pub(crate) fn handoff_context(&self) -> &CsharpHandoffProjectContext {
        &self.handoff
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_model_policy_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    project_context: &CsharpModelProjectContext,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    let catalog = &project_context.catalog;
    if catalog.context_sets.is_empty() {
        return;
    }

    add_resource_queries(
        path,
        root,
        catalog,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_legacy_raw_sql_queries(
        path,
        root,
        catalog,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_legacy_execute_sql_queries(
        path,
        root,
        catalog,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_model_writes(
        path,
        root,
        catalog,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_sensitive_response_selection(
        path,
        root,
        catalog,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_legacy_raw_sql_queries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    catalog: &ModelCatalog,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        if terminal_method(&function_text) != Some("FromSql") {
            continue;
        }
        let arguments = arguments(&invocation);
        // EF Core's obsolete FromSql overload parameterizes a direct
        // FormattableString or explicit format arguments. The unsafe legacy
        // shape is a single String value that was composed beforehand.
        if arguments.len() != 1 || arguments[0].kind().as_ref() == "interpolated_string_expression"
        {
            continue;
        }
        let receiver = function_text.strip_suffix(".FromSql").unwrap_or_default();
        let Some(entity) = entity_for_set(root, &invocation, receiver, catalog) else {
            continue;
        };
        let query = preceding_local_initializer(root, &invocation, &arguments[0])
            .unwrap_or_else(|| arguments[0].clone());
        push(
            path,
            &invocation,
            &query,
            EvidenceKind::Sink,
            Capability::DatabaseQuery,
            "csharp-ef-legacy-from-sql-query",
            "query",
            &["CWE-89"],
            &[
                "ef-core",
                "database",
                "sql",
                "legacy-from-sql",
                "single-string-overload",
                &format!("model:{entity}"),
            ],
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_legacy_execute_sql_queries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    catalog: &ModelCatalog,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if function.kind().as_ref() != "member_access_expression" {
            continue;
        }
        let Some(receiver) = function.field("expression") else {
            continue;
        };
        let Some(method) = function.field("name") else {
            continue;
        };
        let method_text = compact(method.text().as_ref());
        let method_name = method_text.split('<').next().unwrap_or_default();
        if !matches!(
            method_name,
            "ExecuteSqlCommand" | "ExecuteSqlCommandAsync" | "SqlQuery" | "SqlQueryRaw"
        ) {
            continue;
        }
        let receiver = compact(receiver.text().as_ref());
        let Some(context) = receiver.strip_suffix(".Database") else {
            continue;
        };
        let Some(context_type) = variable_type(root, &invocation, context) else {
            continue;
        };
        if !catalog.context_sets.contains_key(short_type(&context_type)) {
            continue;
        }
        let Some(query) = arguments(&invocation).into_iter().next() else {
            continue;
        };
        push(
            path,
            &invocation,
            &query,
            EvidenceKind::Sink,
            Capability::DatabaseQuery,
            if method_name.starts_with("SqlQuery") {
                "csharp-ef-database-sql-query"
            } else {
                "csharp-ef-legacy-execute-sql-command"
            },
            "query",
            &["CWE-89"],
            &[
                if method_name == "SqlQueryRaw" {
                    "ef-core"
                } else {
                    "entity-framework"
                },
                "database",
                "sql",
                if method_name.starts_with("SqlQuery") {
                    "database-sql-query"
                } else {
                    "legacy-execute-sql-command"
                },
            ],
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn preceding_local_initializer<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    value: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let value_text = value.text();
    let name = simple_identifier(value_text.trim())?;
    let method = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration")?
        .range();
    root.dfs()
        .filter(|node| {
            node.kind().as_ref() == "variable_declarator"
                && method.start <= node.range().start
                && node.range().end <= method.end
                && node.range().start < use_site.range().start
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
        })
        .filter_map(|node| {
            node.field("value")
                .or_else(|| node.children().filter(|child| child.is_named()).last())
        })
        .last()
}

fn merge_catalog(target: &mut ModelCatalog, source: ModelCatalog) {
    for (context, sets) in source.context_sets {
        target.context_sets.entry(context).or_default().extend(sets);
    }
    for (model, fields) in source.sensitive_fields {
        target
            .sensitive_fields
            .entry(model)
            .or_default()
            .extend(fields);
    }
}

fn build_catalog(root: &Node<'_, StrDoc<SupportLang>>) -> ModelCatalog {
    let mut catalog = ModelCatalog::default();
    for class in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "class_declaration")
    {
        let Some(name_node) = class.field("name") else {
            continue;
        };
        let name = name_node.text().into_owned();
        let compact_class = compact(class.text().as_ref());
        let header = compact_class.split('{').next().unwrap_or_default();
        let is_context = header.contains(":DbContext")
            || header.contains(":Microsoft.EntityFrameworkCore.DbContext");
        let mut sets = BTreeMap::new();
        let mut sensitive = BTreeSet::new();
        for property in class
            .dfs()
            .filter(|node| node.kind().as_ref() == "property_declaration")
            .filter(|node| {
                node.ancestors()
                    .find(|ancestor| ancestor.kind().as_ref() == "class_declaration")
                    .is_some_and(|owner| owner.range() == class.range())
            })
        {
            let Some(property_name) = property.field("name") else {
                continue;
            };
            let property_name = property_name.text().into_owned();
            let property_type = property
                .field("type")
                .map(|kind| compact(kind.text().as_ref()))
                .unwrap_or_default();
            if is_context {
                if let Some(entity) = generic_argument(&property_type, "DbSet") {
                    sets.insert(property_name, entity.to_string());
                }
            } else if is_sensitive_field(&property_name) {
                sensitive.insert(property_name);
            }
        }
        if is_context && !sets.is_empty() {
            catalog.context_sets.insert(name.clone(), sets);
        }
        if !sensitive.is_empty() {
            catalog.sensitive_fields.insert(name, sensitive);
        }
    }
    catalog
}

#[allow(clippy::too_many_arguments)]
fn add_resource_queries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    catalog: &ModelCatalog,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        if comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let Some(method) = terminal_method(&function_text) else {
            continue;
        };
        if !matches!(
            method,
            "Find"
                | "FindAsync"
                | "First"
                | "FirstAsync"
                | "FirstOrDefault"
                | "FirstOrDefaultAsync"
                | "Single"
                | "SingleAsync"
                | "SingleOrDefault"
                | "SingleOrDefaultAsync"
                | "ToList"
                | "ToListAsync"
                | "ToArray"
                | "ToArrayAsync"
        ) {
            continue;
        }
        let receiver_text = function_text
            .strip_suffix(&format!(".{method}"))
            .unwrap_or_default();
        let set_text = receiver_text
            .split(".Where(")
            .next()
            .unwrap_or(receiver_text);
        let Some(entity) = entity_for_set(root, &invocation, set_text, catalog) else {
            continue;
        };
        let arguments = arguments(&invocation);
        let filter = if matches!(method, "Find" | "FindAsync") {
            arguments.first().cloned()
        } else if receiver_text.contains(".Where(") {
            function.field("expression")
        } else {
            arguments.first().cloned()
        };
        let Some(filter) = filter else {
            continue;
        };
        let filter_text = compact(filter.text().as_ref());
        if !matches!(method, "Find" | "FindAsync") && !looks_like_key_filter(&filter_text) {
            continue;
        }
        if owner_or_tenant_scoped(&filter_text) {
            push(
                path,
                &invocation,
                &filter,
                EvidenceKind::Validation,
                Capability::ResourceAccess,
                "csharp-ef-owner-scoped-query-control",
                "filter",
                &["CWE-639"],
                &[
                    "ef-core",
                    "resource-access",
                    "owner-or-tenant-scoped",
                    &format!("model:{entity}"),
                    &format!("operation:{method}"),
                ],
                Some(ResourcePolicyContext {
                    state: ResourcePolicyState::OwnerScoped,
                    basis: "same EF predicate compares the resource to the authenticated principal"
                        .to_string(),
                }),
                comments,
                conditional,
                literals,
                evidence,
            );
        } else {
            push(
                path,
                &invocation,
                &filter,
                EvidenceKind::Sink,
                Capability::ResourceAccess,
                "csharp-ef-unscoped-resource-query",
                "filter",
                &["CWE-639"],
                &[
                    "ef-core",
                    "resource-access",
                    "request-selected-key",
                    "needs-verification",
                    "verify-global-query-filter-or-resource-authorization",
                    &format!("model:{entity}"),
                    &format!("operation:{method}"),
                ],
                Some(ResourcePolicyContext {
                    state: ResourcePolicyState::Unknown,
                    basis: "request-selected key is present without an observed same-query owner or tenant predicate; verify global query filters and post-load resource authorization"
                        .to_string(),
                }),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_model_writes<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    catalog: &ModelCatalog,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let method = terminal_method(&function_text).unwrap_or_default();
        let call_arguments = arguments(&invocation);
        let Some(input) = call_arguments.first() else {
            continue;
        };
        if matches!(method, "Update" | "UpdateRange" | "Add" | "AddAsync") {
            let receiver = function_text
                .strip_suffix(&format!(".{method}"))
                .unwrap_or_default();
            let Some(entity) = entity_for_set(root, &invocation, receiver, catalog) else {
                continue;
            };
            let Some(sensitive) = catalog.sensitive_fields.get(&entity) else {
                continue;
            };
            if simple_identifier(input.text().trim()).is_some() {
                push_mass_assignment(
                    path,
                    &invocation,
                    input,
                    &entity,
                    sensitive,
                    method,
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if input.kind().as_ref() == "object_creation_expression" {
                let assigned = assigned_property_names(input);
                if assigned.is_disjoint(sensitive) {
                    push(
                        path,
                        &invocation,
                        input,
                        EvidenceKind::Validation,
                        Capability::ResourceAccess,
                        "csharp-ef-explicit-field-update-control",
                        "assigned_fields",
                        &["CWE-915"],
                        &[
                            "ef-core",
                            "model-write",
                            "explicit-field-mapping",
                            &format!("model:{entity}"),
                        ],
                        None,
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
        } else if method == "SetValues" && function_text.contains(".CurrentValues.SetValues") {
            let input_text = input.text();
            let Some(input_name) = simple_identifier(input_text.trim()) else {
                continue;
            };
            let Some(input_type) = variable_type(root, &invocation, input_name) else {
                continue;
            };
            let input_type = short_type(&input_type).to_string();
            let Some(sensitive) = catalog.sensitive_fields.get(&input_type) else {
                continue;
            };
            push_mass_assignment(
                path,
                &invocation,
                input,
                &input_type,
                sensitive,
                method,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_mass_assignment<'tree>(
    path: &str,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    input: &Node<'tree, StrDoc<SupportLang>>,
    model: &str,
    sensitive: &BTreeSet<String>,
    method: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let fields = sensitive.iter().cloned().collect::<Vec<_>>().join(",");
    push(
        path,
        invocation,
        input,
        EvidenceKind::Sink,
        Capability::ResourceAccess,
        "csharp-ef-sensitive-model-mass-assignment",
        "assigned_fields",
        &["CWE-915"],
        &[
            "ef-core",
            "mass-assignment",
            "model-write",
            &format!("model:{model}"),
            &format!("sensitive-fields:{fields}"),
            &format!("operation:{method}"),
        ],
        None,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_sensitive_response_selection<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    catalog: &ModelCatalog,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for invocation in invocations(root) {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        if terminal_method(&compact(function.text().as_ref())) != Some("GetProperty") {
            continue;
        }
        let Some(selector) = arguments(&invocation).first().cloned() else {
            continue;
        };
        let selector_text = selector.text();
        let Some(selector_name) = simple_identifier(selector_text.trim()) else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let Some(model) = reflection_model(root, &invocation, &function_text) else {
            continue;
        };
        let Some(sensitive) = catalog.sensitive_fields.get(&model) else {
            continue;
        };
        if !reaches_response(&invocation) {
            continue;
        }
        if let Some(allowlist) =
            safe_literal_allowlist(root, &invocation, selector_name, sensitive, literals)
        {
            push(
                path,
                &allowlist,
                &selector,
                EvidenceKind::Validation,
                Capability::ResourceAccess,
                "csharp-sensitive-field-allowlist-control",
                "field_selector",
                &["CWE-200"],
                &[
                    "aspnet-core",
                    "reflection",
                    "response-field-selection",
                    "literal-allowlist",
                    &format!("model:{model}"),
                ],
                None,
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        let fields = sensitive.iter().cloned().collect::<Vec<_>>().join(",");
        push(
            path,
            &invocation,
            &selector,
            EvidenceKind::Sink,
            Capability::ResourceAccess,
            "csharp-request-selected-sensitive-response-field",
            "field_selector",
            &["CWE-200"],
            &[
                "aspnet-core",
                "reflection",
                "response-field-selection",
                &format!("model:{model}"),
                &format!("sensitive-fields:{fields}"),
            ],
            None,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn entity_for_set(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    set: &str,
    catalog: &ModelCatalog,
) -> Option<String> {
    let first = set.split('.').next()?;
    if let Some(name) = simple_identifier(first) {
        let observed = variable_type(root, use_site, name)?;
        if let Some(entity) = generic_argument(&compact(&observed), "DbSet") {
            return Some(entity.to_string());
        }
    }
    let mut parts = set.split('.');
    let context = parts.next()?;
    let property = parts.next()?;
    let context_type = short_type(&variable_type(root, use_site, context)?).to_string();
    catalog
        .context_sets
        .get(&context_type)?
        .get(property)
        .cloned()
}

fn variable_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
) -> Option<String> {
    let scope = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration")
        .map(|node| node.range());
    let class = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "class_declaration")
        .map(|node| node.range());
    let mut candidates = root
        .dfs()
        .filter(|node| node.range().start < use_site.range().start)
        .filter_map(|node| {
            if node.kind().as_ref() == "parameter"
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
                && scope.as_ref().is_some_and(|range| {
                    range.start <= node.range().start && node.range().end <= range.end
                })
            {
                return Some((node.range().start, node.field("type")?.text().into_owned()));
            }
            if node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|field| field.text().trim() == name)
            {
                let declaration = node.parent()?;
                let mut observed = declaration.field("type")?.text().into_owned();
                if observed.trim() == "var" {
                    let declaration_text = compact(node.text().as_ref());
                    if let Some(inferred) = declaration_text
                        .split_once("=new")
                        .and_then(|(_, tail)| tail.split(['(', '{']).next())
                        .filter(|inferred| !inferred.is_empty())
                    {
                        observed = inferred.to_string();
                    }
                }
                let in_method = scope.as_ref().is_some_and(|range| {
                    range.start <= node.range().start && node.range().end <= range.end
                });
                let in_class = class.as_ref().is_some_and(|range| {
                    range.start <= node.range().start && node.range().end <= range.end
                });
                if in_method || in_class {
                    return Some((node.range().start, observed));
                }
            }
            None
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(offset, _)| *offset);
    candidates.pop().map(|(_, observed)| observed)
}

fn reflection_model(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_site: &Node<'_, StrDoc<SupportLang>>,
    function: &str,
) -> Option<String> {
    let receiver = function.strip_suffix(".GetProperty")?;
    if let Some(model) = receiver
        .strip_prefix("typeof(")
        .and_then(|value| value.strip_suffix(')'))
    {
        return Some(short_type(model).to_string());
    }
    let variable = receiver.strip_suffix(".GetType()")?;
    variable_type(root, use_site, variable).map(|observed| short_type(&observed).to_string())
}

fn safe_literal_allowlist<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    use_site: &Node<'tree, StrDoc<SupportLang>>,
    selector: &str,
    sensitive: &BTreeSet<String>,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let method = use_site
        .ancestors()
        .find(|node| node.kind().as_ref() == "method_declaration")?;
    for contains in method.dfs().filter(|node| {
        node.kind().as_ref() == "invocation_expression"
            && node.range().start < use_site.range().start
    }) {
        let function = compact(contains.field("function")?.text().as_ref());
        let allowlist = function.strip_suffix(".Contains")?;
        if arguments(&contains)
            .first()
            .is_none_or(|argument| argument.text().trim() != selector)
        {
            continue;
        }
        let rejecting_guard = contains
            .ancestors()
            .find(|node| node.kind().as_ref() == "if_statement")
            .filter(|guard| {
                guard.field("condition").is_some_and(|condition| {
                    compact(condition.text().as_ref())
                        == format!("!{allowlist}.Contains({selector})")
                })
            })
            .and_then(|guard| guard.field("consequence"))
            .is_some_and(|consequence| reachability::always_terminates(&consequence, literals));
        if !rejecting_guard {
            continue;
        }
        let declaration = root.dfs().find(|node| {
            node.kind().as_ref() == "variable_declarator"
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == allowlist)
                && node.range().start < contains.range().start
                && method.range().start <= node.range().start
                && node.range().end <= method.range().end
        })?;
        let values = declaration
            .dfs()
            .filter(|node| node.kind().as_ref() == "string_literal")
            .filter_map(|node| unquote(node.text().as_ref()).map(str::to_string))
            .collect::<BTreeSet<_>>();
        if !values.is_empty() && values.is_disjoint(sensitive) {
            return Some(declaration);
        }
    }
    None
}

fn reaches_response(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors().any(|ancestor| {
        ancestor.kind().as_ref() == "invocation_expression"
            && ancestor.field("function").is_some_and(|function| {
                matches!(
                    terminal_method(&compact(function.text().as_ref())),
                    Some("Ok" | "Json" | "JsonResult")
                )
            })
    })
}

fn owner_or_tenant_scoped(filter: &str) -> bool {
    let principals = [
        "User.FindFirstValue(",
        "HttpContext.User.FindFirstValue(",
        "User.Identity.Name",
        "HttpContext.User.Identity.Name",
    ];
    ["OwnerId", "UserId", "AccountId", "TenantId"]
        .iter()
        .any(|field| {
            principals
                .iter()
                .any(|principal| filter.contains(&format!(".{field}=={principal}")))
        })
}

fn looks_like_key_filter(filter: &str) -> bool {
    filter.contains(".Id==")
        || filter.contains(".ID==")
        || filter.contains(".Id.Equals(")
        || filter.contains(".ID.Equals(")
        || ["OrderId", "OwnerId", "UserId", "AccountId", "TenantId"]
            .iter()
            .any(|field| filter.contains(&format!(".{field}==")))
}

fn assigned_property_names(node: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    node.dfs()
        .filter(|child| child.kind().as_ref() == "assignment_expression")
        .filter_map(|child| child.field("left"))
        .map(|left| {
            compact(left.text().as_ref())
                .trim_start_matches("this.")
                .to_string()
        })
        .collect()
}

fn is_sensitive_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "role"
            | "roles"
            | "isadmin"
            | "isadministrator"
            | "password"
            | "passwordhash"
            | "securitystamp"
            | "concurrencystamp"
            | "totpsecret"
            | "mfarecoverycodes"
            | "apikey"
            | "secret"
            | "ownerid"
            | "userid"
            | "tenantid"
            | "accountid"
            | "balance"
    )
}

fn generic_argument<'a>(observed: &'a str, generic: &str) -> Option<&'a str> {
    let marker = format!("{generic}<");
    let start = observed.rfind(&marker)? + marker.len();
    let tail = &observed[start..];
    let end = tail.find('>')?;
    Some(short_type(&tail[..end]))
}

fn terminal_method(function: &str) -> Option<&str> {
    function.rsplit('.').next()
}

fn arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .filter_map(|argument| {
                    if argument.kind().as_ref() == "argument" {
                        argument.children().find(|child| child.is_named())
                    } else {
                        Some(argument)
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
        .collect()
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut chars = text.chars();
    let first = chars.next()?;
    (first == '_' || first.is_alphabetic()).then_some(())?;
    chars
        .all(|character| character == '_' || character.is_alphanumeric())
        .then_some(text)
}

fn short_type(text: &str) -> &str {
    text.trim()
        .trim_end_matches('?')
        .rsplit('.')
        .next()
        .unwrap_or(text)
}

fn unquote(text: &str) -> Option<&str> {
    text.strip_prefix('"')?.strip_suffix('"')
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
    capture: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    rule_id: &str,
    capture_role: &str,
    cwes: &[&str],
    tags: &[&str],
    resource_policy: Option<ResourcePolicyContext>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    evidence.push(Evidence {
        id: evidence_id(rule_id, path, node.range().start, node.range().end),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::from([(
            capture_role.to_string(),
            Capture {
                text: capture.text().into_owned(),
                location: location(path, capture),
            },
        )]),
        cwe_candidates: cwes.iter().map(|cwe| (*cwe).to_string()).collect(),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            resource_policy,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}

fn evidence_id(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
