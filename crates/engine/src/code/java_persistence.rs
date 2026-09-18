use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-persistence-policy 1";
const SENSITIVE_FIELDS: &[&str] = &[
    "admin",
    "apikey",
    "authorities",
    "authority",
    "availablecredit",
    "credit",
    "enabled",
    "owner",
    "password",
    "permissions",
    "role",
    "status",
    "tenant",
    "user",
];

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_persistence_observations<'tree>(
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
    let imports = imports(root);
    let declarations = declared_types(root);
    let receivers = receiver_types(root);
    add_query_observations(
        path,
        root,
        &imports,
        &declarations,
        &receivers,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_mapping_observations(
        path,
        root,
        &imports,
        &declarations,
        &receivers,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_query_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    receivers: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let entity_manager = imported_any_exact(
        imports,
        declarations,
        &[
            "jakarta.persistence.EntityManager",
            "javax.persistence.EntityManager",
        ],
        "EntityManager",
    );
    let persistence_query = imported_any_exact(
        imports,
        declarations,
        &["jakarta.persistence.Query", "javax.persistence.Query"],
        "Query",
    );
    let jdbc_template = imported_exact(
        imports,
        declarations,
        "org.springframework.jdbc.core.JdbcTemplate",
        "JdbcTemplate",
    );
    let named_jdbc = imported_exact(
        imports,
        declarations,
        "org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate",
        "NamedParameterJdbcTemplate",
    );

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let (Some(object), Some(name)) = (invocation.field("object"), invocation.field("name"))
        else {
            continue;
        };
        let operation = name.text();
        let receiver = receivers.get(object.text().trim()).map(String::as_str);
        let jpa = entity_manager
            && receiver == Some("EntityManager")
            && matches!(operation.as_ref(), "createNativeQuery" | "createQuery");
        let jdbc = ((jdbc_template && receiver == Some("JdbcTemplate"))
            || (named_jdbc && receiver == Some("NamedParameterJdbcTemplate")))
            && matches!(
                operation.as_ref(),
                "query"
                    | "queryForList"
                    | "queryForMap"
                    | "queryForObject"
                    | "update"
                    | "execute"
                    | "batchUpdate"
            );
        if (jpa || jdbc)
            && let Some(query) = first_argument(&invocation)
        {
            evidence.retain(|item| {
                !(item.rule_id == "java-database-query"
                    && item.location.path == path
                    && item.location.start.byte_offset == invocation.range().start)
            });
            push(
                path,
                &invocation,
                &query,
                "java-typed-persistence-query",
                EvidenceKind::Sink,
                Capability::DatabaseQuery,
                "query",
                &["CWE-89"],
                &[
                    "database",
                    if jpa { "jpa" } else { "spring-jdbc" },
                    operation.as_ref(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
            let args = arguments(&invocation);
            if named_jdbc && receiver == Some("NamedParameterJdbcTemplate") && args.len() >= 2 {
                push_two_captures(
                    path,
                    &invocation,
                    &args[0],
                    &args[1],
                    "java-named-jdbc-parameterization-control",
                    Capability::SqlParameterization,
                    "query",
                    "parameters",
                    &["CWE-89"],
                    &["database", "spring-jdbc", "named-parameter"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if operation.as_ref() == "setParameter" && persistence_query && receiver == Some("Query") {
            let arguments = arguments(&invocation);
            if arguments.len() >= 2 {
                push_two_captures(
                    path,
                    &invocation,
                    &arguments[0],
                    &arguments[1],
                    "java-jpa-query-parameterization-control",
                    Capability::SqlParameterization,
                    "parameter",
                    "value",
                    &["CWE-89"],
                    &["database", "jpa", "parameter-binding"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }

    let spring_query = imported_exact(
        imports,
        declarations,
        "org.springframework.data.jpa.repository.Query",
        "Query",
    );
    let spring_param = imported_exact(
        imports,
        declarations,
        "org.springframework.data.repository.query.Param",
        "Param",
    );
    if spring_query {
        for method in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_declaration")
        {
            let Some(annotation) = annotations(&method)
                .into_iter()
                .find(|annotation| annotation_head(annotation.text().as_ref()) == "Query")
            else {
                continue;
            };
            push(
                path,
                &annotation,
                &annotation,
                "java-spring-data-custom-query",
                EvidenceKind::SensitiveOperation,
                Capability::DatabaseQuery,
                "query",
                &["CWE-89"],
                &[
                    "database",
                    "spring-data",
                    if annotation.text().contains("nativeQuery = true") {
                        "native-query"
                    } else {
                        "jpql"
                    },
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
            if spring_param && annotation.text().contains(':') && method.text().contains("@Param(")
            {
                push_without_capture(
                    path,
                    &method,
                    "java-spring-data-named-parameter-control",
                    EvidenceKind::Validation,
                    Capability::SqlParameterization,
                    &["CWE-89"],
                    &["database", "spring-data", "named-parameter"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_mapping_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    receivers: &BTreeMap<String, String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let spring_bean_utils = imported_exact(
        imports,
        declarations,
        "org.springframework.beans.BeanUtils",
        "BeanUtils",
    );
    let commons_bean_utils = imported_exact(
        imports,
        declarations,
        "org.apache.commons.beanutils.BeanUtils",
        "BeanUtils",
    );
    let object_mapper = imported_exact(
        imports,
        declarations,
        "com.fasterxml.jackson.databind.ObjectMapper",
        "ObjectMapper",
    );
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let sources = source_parameters(path, &method, evidence);
        if sources.is_empty() || !has_repository_save(&method, receivers) {
            continue;
        }
        for invocation in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "method_invocation")
        {
            let (Some(object), Some(name)) = (invocation.field("object"), invocation.field("name"))
            else {
                continue;
            };
            let operation = name.text();
            let args = arguments(&invocation);
            if matches!(operation.as_ref(), "save" | "saveAndFlush")
                && receivers
                    .get(object.text().trim())
                    .is_some_and(|kind| kind.ends_with("Repository"))
                && let Some(input) = args.first()
                && let Some(source) = sources
                    .iter()
                    .find(|source| input.text().trim() == source.name)
            {
                push_related(
                    path,
                    &invocation,
                    input,
                    "java-spring-data-request-entity-mass-assignment",
                    EvidenceKind::SensitiveOperation,
                    Capability::ResourceAccess,
                    "input",
                    &["CWE-915"],
                    &["mass-assignment", "request-entity", "direct-save"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                    vec![source.evidence_id.clone()],
                );
            }

            if operation.as_ref() == "copyProperties"
                && object.text().as_ref() == "BeanUtils"
                && (spring_bean_utils || commons_bean_utils)
                && args.len() >= 2
            {
                let (source_value, target) = if spring_bean_utils {
                    (&args[0], &args[1])
                } else {
                    (&args[1], &args[0])
                };
                let Some(source) = sources
                    .iter()
                    .find(|source| source_value.text().trim() == source.name)
                else {
                    continue;
                };
                if !method
                    .text()
                    .contains(&format!("save({})", target.text().trim()))
                {
                    continue;
                }
                let ignored = spring_bean_utils && args.len() > 2;
                push_related(
                    path,
                    &invocation,
                    source_value,
                    if ignored {
                        "java-bean-copy-ignore-list-control"
                    } else {
                        "java-bean-copy-persistent-mass-assignment"
                    },
                    if ignored {
                        EvidenceKind::Validation
                    } else {
                        EvidenceKind::SensitiveOperation
                    },
                    Capability::ResourceAccess,
                    "input",
                    &["CWE-915"],
                    if ignored {
                        &["mass-assignment", "bean-copy", "ignore-list"]
                    } else {
                        &["mass-assignment", "bean-copy", "persistent-target"]
                    },
                    comments,
                    conditional,
                    literals,
                    evidence,
                    vec![source.evidence_id.clone()],
                );
            }

            if operation.as_ref() == "readValue"
                && object_mapper
                && let Some(reader) = invocation.field("object")
                && let Some(target) = jackson_update_target(reader.text().as_ref(), receivers)
                && let Some(source_value) = args.first()
                && let Some(source) = sources
                    .iter()
                    .find(|source| source_value.text().trim() == source.name)
                && method.text().contains(&format!("save({target})"))
            {
                push_related(
                    path,
                    &invocation,
                    source_value,
                    "java-jackson-persistent-update-mass-assignment",
                    EvidenceKind::SensitiveOperation,
                    Capability::ResourceAccess,
                    "input",
                    &["CWE-915"],
                    &["mass-assignment", "jackson", "reader-for-updating"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                    vec![source.evidence_id.clone()],
                );
            }

            let Some(property) = operation.strip_prefix("set") else {
                continue;
            };
            let normalized = normalize(property);
            if !SENSITIVE_FIELDS.contains(&normalized.as_str()) || args.is_empty() {
                continue;
            }
            let value = &args[0];
            let Some(source) = sources
                .iter()
                .find(|source| contains_identifier(value.text().as_ref(), &source.name))
            else {
                continue;
            };
            push_related(
                path,
                &invocation,
                value,
                "java-sensitive-field-explicit-request-assignment",
                EvidenceKind::SensitiveOperation,
                Capability::ResourceAccess,
                "value",
                &["CWE-915", "CWE-862"],
                &[
                    "explicit-field-mapping",
                    "request-data",
                    &format!("field:{normalized}"),
                    if value.text().contains("encoder.encode(") {
                        "password-encoding-observed"
                    } else {
                        "verify-field-authority"
                    },
                ],
                comments,
                conditional,
                literals,
                evidence,
                vec![source.evidence_id.clone()],
            );
        }
    }
}

#[derive(Clone)]
struct SourceParameter {
    name: String,
    evidence_id: String,
}

fn source_parameters(
    path: &str,
    method: &Node<'_, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) -> Vec<SourceParameter> {
    let parameters = method
        .field("parameters")
        .map(|parameters| parameters.children().collect::<Vec<_>>())
        .unwrap_or_default();
    parameters
        .into_iter()
        .filter(|parameter| parameter.kind().as_ref() == "formal_parameter")
        .filter_map(|parameter| {
            let name = parameter.field("name")?;
            let item = evidence.iter().find(|item| {
                item.kind == EvidenceKind::Source
                    && item.location.path == path
                    && item.location.start.byte_offset == name.range().start
                    && item.capability == Capability::HttpRequestData
            })?;
            Some(SourceParameter {
                name: name.text().into_owned(),
                evidence_id: item.id.clone(),
            })
        })
        .collect()
}

fn has_repository_save(
    method: &Node<'_, StrDoc<SupportLang>>,
    receivers: &BTreeMap<String, String>,
) -> bool {
    method.dfs().any(|invocation| {
        invocation.kind().as_ref() == "method_invocation"
            && invocation
                .field("name")
                .is_some_and(|name| matches!(name.text().as_ref(), "save" | "saveAndFlush"))
            && invocation.field("object").is_some_and(|object| {
                receivers
                    .get(object.text().trim())
                    .is_some_and(|kind| kind.ends_with("Repository"))
            })
    })
}

// New ambiguous JDBC method names require a native receiver identity. Keep
// the existing distinctive executeQuery/executeUpdate rules compatible.
pub(super) fn jdbc_statement_receiver(
    root: &Node<'_, StrDoc<SupportLang>>,
    invocation: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    invocation
        .field("object")
        .is_some_and(|receiver| typed_database_receiver(root, &receiver, "java.sql.Statement", 8))
}

pub(super) fn typed_database_receiver(
    root: &Node<'_, StrDoc<SupportLang>>,
    expression: &Node<'_, StrDoc<SupportLang>>,
    canonical: &str,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let short = canonical.rsplit('.').next().unwrap_or(canonical);
    if expression.kind().as_ref() == "object_creation_expression" {
        return expression.field("type").is_some_and(|ty| {
            ty.text() == canonical
                || ty.text() == short
                    && imported_exact(&imports(root), &declared_types(root), canonical, short)
        });
    }
    if expression.kind().as_ref() == "method_invocation" {
        let Some(object) = expression.field("object") else {
            return false;
        };
        let operation = expression.field("name").map(|n| n.text().to_string());
        return short == "Statement"
            && operation.as_deref() == Some("createStatement")
            && typed_database_receiver(root, &object, "java.sql.Connection", depth - 1);
    }
    let name = expression.text();
    let explicit_this = name.starts_with("this.");
    let name = name.strip_prefix("this.").unwrap_or(&name);
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
    {
        return false;
    }
    let class = expression
        .ancestors()
        .find(|n| {
            matches!(
                n.kind().as_ref(),
                "class_declaration" | "record_declaration"
            )
        })
        .map(|n| n.range());
    let mut locals = Vec::new();
    let mut fields = Vec::new();
    for binding in root.dfs().filter(|n| {
        matches!(
            n.kind().as_ref(),
            "variable_declarator" | "formal_parameter"
        )
    }) {
        if binding.field("name").is_none_or(|n| n.text() != name) {
            continue;
        }
        let declaration = if binding.kind().as_ref() == "formal_parameter" {
            binding.clone()
        } else {
            let Some(parent) = binding.parent() else {
                continue;
            };
            parent
        };
        let Some(ty) = declaration.field("type") else {
            continue;
        };
        if declaration.kind().as_ref() == "field_declaration" {
            let owner = binding
                .ancestors()
                .find(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "class_declaration" | "record_declaration"
                    )
                })
                .map(|n| n.range());
            if owner == class {
                fields.push((binding, ty.text().to_string()));
            }
        } else if !explicit_this && binding.range().end <= expression.range().start {
            let scope = binding.ancestors().find(|n| {
                matches!(
                    n.kind().as_ref(),
                    "block"
                        | "lambda_expression"
                        | "method_declaration"
                        | "constructor_declaration"
                )
            });
            if scope.is_some_and(|n| {
                n.range().start <= expression.range().start
                    && expression.range().end <= n.range().end
            }) {
                locals.push((binding, ty.text().to_string()));
            }
        }
    }
    locals.sort_by_key(|(binding, _)| binding.range().start);
    let binding = locals.last().or_else(|| fields.first());
    let Some((binding, ty)) = binding else {
        return false;
    };
    let ty = ty.split('<').next().unwrap_or(ty);
    if ty == canonical {
        return true;
    }
    let generic_shadow = root.dfs().any(|n| {
        n.kind().as_ref() == "type_parameter"
            && n.children()
                .any(|child| child.kind().as_ref() == "type_identifier" && child.text() == short)
            && n.ancestors()
                .find(|owner| {
                    matches!(
                        owner.kind().as_ref(),
                        "method_declaration"
                            | "class_declaration"
                            | "interface_declaration"
                            | "record_declaration"
                    )
                })
                .is_some_and(|owner| {
                    owner.range().start <= expression.range().start
                        && expression.range().end <= owner.range().end
                })
    });
    if ty == short
        && !generic_shadow
        && imported_exact(&imports(root), &declared_types(root), canonical, short)
    {
        return true;
    }
    ty == "var"
        && binding
            .field("value")
            .is_some_and(|value| typed_database_receiver(root, &value, canonical, depth - 1))
}

fn receiver_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    for declaration in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "field_declaration" | "local_variable_declaration"
        )
    }) {
        let Some(kind) = declaration.field("type") else {
            continue;
        };
        let kind = kind.text().trim().to_string();
        for variable in declaration
            .children()
            .filter(|node| node.kind().as_ref() == "variable_declarator")
        {
            if let Some(name) = variable.field("name") {
                result.insert(name.text().into_owned(), kind.clone());
            }
        }
    }
    result
}

fn jackson_update_target(text: &str, receivers: &BTreeMap<String, String>) -> Option<String> {
    let compact = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let (mapper, target) = compact.split_once(".readerForUpdating(")?;
    let target = target.strip_suffix(')')?;
    (receivers
        .get(mapper)
        .is_some_and(|kind| kind == "ObjectMapper")
        && target.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_alphabetic()
                || (index > 0 && character.is_ascii_digit())
        }))
    .then(|| target.to_string())
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
    !declarations.contains(short)
        && (imports.contains(canonical)
            || canonical
                .rsplit_once('.')
                .is_some_and(|(namespace, _)| imports.contains(&format!("{namespace}.*"))))
}

fn imported_any_exact(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonicals: &[&str],
    short: &str,
) -> bool {
    canonicals
        .iter()
        .any(|canonical| imported_exact(imports, declarations, canonical, short))
}

fn annotations<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.children()
        .find(|child| child.kind().as_ref() == "modifiers")
        .map(|modifiers| {
            modifiers
                .children()
                .filter(|annotation| {
                    matches!(
                        annotation.kind().as_ref(),
                        "annotation" | "marker_annotation"
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn annotation_head(text: &str) -> &str {
    text.trim()
        .trim_start_matches('@')
        .split(['(', ' ', '\n', '\r', '\t'])
        .next()
        .unwrap_or_default()
}

fn arguments<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn first_argument<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    arguments(invocation).into_iter().next()
}

fn normalize(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn contains_identifier(text: &str, name: &str) -> bool {
    text.match_indices(name).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + name.len()..].chars().next();
        !before.is_some_and(|character| character == '_' || character.is_alphanumeric())
            && !after.is_some_and(|character| character == '_' || character.is_alphanumeric())
    })
}

#[allow(clippy::too_many_arguments)]
fn push<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    captured: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_related(
        path,
        node,
        captured,
        rule_id,
        kind,
        capability,
        role,
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
        Vec::new(),
    );
}

#[allow(clippy::too_many_arguments)]
fn push_related<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    captured: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    role: &str,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
    related_evidence: Vec<String>,
) {
    push_evidence(
        path,
        node,
        rule_id,
        kind,
        capability,
        BTreeMap::from([(
            role.to_string(),
            Capture {
                text: captured.text().into_owned(),
                location: location(path, captured),
            },
        )]),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
        related_evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_two_captures<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    first: &Node<'tree, StrDoc<SupportLang>>,
    second: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    capability: Capability,
    first_role: &str,
    second_role: &str,
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
        rule_id,
        EvidenceKind::Validation,
        capability,
        BTreeMap::from([
            (
                first_role.to_string(),
                Capture {
                    text: first.text().into_owned(),
                    location: location(path, first),
                },
            ),
            (
                second_role.to_string(),
                Capture {
                    text: second.text().into_owned(),
                    location: location(path, second),
                },
            ),
        ]),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
        Vec::new(),
    );
}

#[allow(clippy::too_many_arguments)]
fn push_without_capture<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
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
        rule_id,
        kind,
        capability,
        BTreeMap::new(),
        cwes,
        tags,
        comments,
        conditional,
        literals,
        evidence,
        Vec::new(),
    );
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    cwes: &[&str],
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
    related_evidence: Vec<String>,
) {
    let id = format!(
        "{path}:{}:{}:{rule_id}",
        node.range().start,
        node.range().end
    );
    if comments.is_in_comment(node.range()) || evidence.iter().any(|item| item.id == id) {
        return;
    }
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
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    });
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
