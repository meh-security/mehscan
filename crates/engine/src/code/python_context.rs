use std::collections::{BTreeMap, BTreeSet, VecDeque};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteAccess,
    HttpRouteContext, Language, Location, Position, Provenance, Resolution, ResourcePolicyContext,
    ResourcePolicyState,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan python-django-project-context 1";
const HANDLER_RULE_ID: &str = "python-django-handler-entrypoint";
const ROUTE_PARAMETER_RULE_ID: &str = "python-django-route-parameter";
const TLS_DISABLED_RULE_ID: &str = "python-http-tls-verification-disabled";
const CSRF_EXEMPT_RULE_ID: &str = "python-django-csrf-exempt-handler";
const TEMPLATE_OUTPUT_RULE_ID: &str = "python-django-template-unsafe-output";
const FLASK_TEMPLATE_OUTPUT_RULE_ID: &str = "python-flask-template-unsafe-output";
const PARAMETER_SINK_RULE_ID: &str = "python-file-local-parameter-sink-summary";
const SOURCE_FILE_CONTENT_WRITE_RULE_ID: &str = "python-source-file-content-write";
const ORM_ACCESS_RULE_ID: &str = "python-django-orm-resource-access";
const ORM_OWNER_CONTROL_RULE_ID: &str = "python-django-orm-owner-scoped-control";
const SENSITIVE_MUTATION_RULE_ID: &str = "python-django-sensitive-field-mutation";
const SERIALIZER_WRITE_RULE_ID: &str = "python-drf-sensitive-serializer-write";
const REQUEST_CREDENTIAL_LOGGING_RULE_ID: &str = "python-request-credential-logging";

#[derive(Clone, Debug, Eq, PartialEq)]
struct PythonRoute {
    path: String,
}

#[derive(Clone, Debug)]
struct Registration {
    module: String,
    path: String,
    target: RegistrationTarget,
}

#[derive(Clone, Debug)]
enum RegistrationTarget {
    Handler(String),
    Include(String),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct PythonProjectContext {
    routes_by_handler: BTreeMap<String, Vec<PythonRoute>>,
    unsafe_template_bindings: BTreeMap<String, BTreeMap<String, String>>,
    serializer_writable_sensitive_fields: BTreeMap<String, Vec<String>>,
    identity: super::python_identity::PythonIdentityContext,
    flask: super::python_flask::PythonFlaskContext,
}

impl PythonProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let sources = sources
            .filter(|(_, language, _)| *language == Language::Python)
            .collect::<Vec<_>>();
        let declared = sources
            .iter()
            .flat_map(|(path, _, source)| declared_handler_keys(path, source))
            .collect::<BTreeSet<_>>();
        let mut registrations = Vec::new();
        for (path, _, source) in &sources {
            registrations.extend(collect_registrations(path, source, &declared));
        }

        let included_modules = registrations
            .iter()
            .filter_map(|registration| match &registration.target {
                RegistrationTarget::Include(module) => Some(module.clone()),
                RegistrationTarget::Handler(_) => None,
            })
            .collect::<BTreeSet<_>>();
        let modules = registrations
            .iter()
            .map(|registration| registration.module.clone())
            .collect::<BTreeSet<_>>();
        let roots = modules
            .difference(&included_modules)
            .cloned()
            .collect::<Vec<_>>();
        let mut prefixes: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut queue = VecDeque::new();
        for root in if roots.is_empty() {
            modules.iter().cloned().collect()
        } else {
            roots
        } {
            prefixes
                .entry(root.clone())
                .or_default()
                .insert(String::new());
            queue.push_back((root, String::new()));
        }
        while let Some((module, prefix)) = queue.pop_front() {
            for registration in registrations.iter().filter(|item| item.module == module) {
                let RegistrationTarget::Include(child) = &registration.target else {
                    continue;
                };
                let child_prefix = join_route(&prefix, &registration.path);
                if prefixes
                    .entry(child.clone())
                    .or_default()
                    .insert(child_prefix.clone())
                {
                    queue.push_back((child.clone(), child_prefix));
                }
            }
        }

        let mut routes_by_handler: BTreeMap<String, Vec<PythonRoute>> = BTreeMap::new();
        for registration in registrations {
            let RegistrationTarget::Handler(handler) = registration.target else {
                continue;
            };
            let module_prefixes = prefixes
                .get(&registration.module)
                .cloned()
                .unwrap_or_else(|| BTreeSet::from([String::new()]));
            for prefix in module_prefixes {
                routes_by_handler
                    .entry(handler.clone())
                    .or_default()
                    .push(PythonRoute {
                        path: join_route(&prefix, &registration.path),
                    });
            }
        }
        for routes in routes_by_handler.values_mut() {
            routes.sort_by(|left, right| left.path.cmp(&right.path));
            routes.dedup();
        }
        Self {
            routes_by_handler,
            unsafe_template_bindings: BTreeMap::new(),
            serializer_writable_sensitive_fields: collect_sensitive_serializer_policies(&sources),
            identity: super::python_identity::PythonIdentityContext::from_sources(
                sources.iter().copied(),
            ),
            flask: super::python_flask::PythonFlaskContext::from_sources(sources.iter().copied()),
        }
    }

    pub(crate) fn with_templates<'a>(
        mut self,
        templates: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        for (path, source) in templates {
            let Some(name) = django_template_name(path) else {
                continue;
            };
            let bindings = unsafe_django_template_bindings(source);
            if !bindings.is_empty() {
                self.unsafe_template_bindings.insert(name, bindings);
            }
        }
        self
    }

    pub(crate) fn with_openapi<'a>(
        mut self,
        documents: impl Iterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        self.flask = self.flask.with_openapi(documents);
        self
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) {
        if language != Language::Python {
            return;
        }
        self.identity.add_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        self.flask.add_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_disabled_tls_observations(path, root, comments, conditional, literals, evidence);
        push_django_orm_observations(path, root, comments, conditional, literals, evidence);
        push_request_credential_logging(path, root, comments, conditional, literals, evidence);
        push_sensitive_field_mutations(path, root, comments, conditional, literals, evidence);
        push_sensitive_serializer_writes(
            path,
            root,
            &self.serializer_writable_sensitive_fields,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_file_local_parameter_sink_summaries(
            path,
            root,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_python_source_file_content_writes(
            path,
            root,
            comments,
            conditional,
            literals,
            evidence,
        );
        push_unsafe_template_outputs(
            path,
            root,
            &self.unsafe_template_bindings,
            comments,
            conditional,
            literals,
            evidence,
        );
        let module = module_from_path(path);
        for function in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "function_definition")
        {
            let Some(name_node) = function.field("name") else {
                continue;
            };
            let name = name_node.text().into_owned();
            let class = enclosing_python_class(&function);
            if class.is_some() && http_method(&name).is_none() {
                continue;
            }
            let handler_key = class.as_ref().map_or_else(
                || format!("{module}:{name}"),
                |class| format!("{module}:{class}"),
            );
            let Some(routes) = self.routes_by_handler.get(&handler_key) else {
                continue;
            };
            let (local_access, mut guards) = handler_access(&function, class.as_deref());
            let access = self.identity.effective_access(local_access, &mut guards);
            let methods = if class.is_some() {
                vec![
                    http_method(&name)
                        .expect("non-HTTP methods were skipped")
                        .to_string(),
                ]
            } else {
                decorated_http_methods(&function)
            };
            let route_contexts = routes
                .iter()
                .flat_map(|route| {
                    methods.iter().map(|method| HttpRouteContext {
                        method: method.clone(),
                        path: route.path.clone(),
                        access,
                        guards: guards.clone(),
                    })
                })
                .collect::<Vec<_>>();

            push_handler_entrypoint(
                path,
                &name_node,
                &handler_key,
                route_contexts.clone(),
                comments,
                conditional,
                literals,
                evidence,
            );
            push_csrf_exempt_context(
                path,
                &function,
                &route_contexts,
                comments,
                conditional,
                literals,
                evidence,
            );
            push_route_parameter_sources(
                path,
                &function,
                &route_contexts,
                comments,
                conditional,
                literals,
                evidence,
            );

            let function_range = function.range();
            for item in evidence.iter_mut().filter(|item| {
                item.location.path == path
                    && item.rule_id != ROUTE_PARAMETER_RULE_ID
                    && item.location.start.byte_offset >= function_range.start
                    && item.location.end.byte_offset <= function_range.end
            }) {
                merge_routes(&mut item.context.http_routes, &route_contexts);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_request_credential_logging<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter(|node| {
        node.kind().as_ref() == "call"
            && node
                .field("function")
                .is_some_and(|callee| python_logging_call(callee.text().trim()))
    }) {
        if comments.is_in_comment(call.range()) {
            continue;
        }
        let Some(function) = call
            .ancestors()
            .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        let arguments = python_call_arguments(&call);
        if arguments.is_empty() {
            continue;
        }
        let Some(origin) = python_logged_credential_origin(&function, &call, &arguments) else {
            continue;
        };
        let message = call
            .children()
            .find(|child| child.kind().as_ref() == "argument_list")
            .unwrap_or_else(|| arguments[0].clone());
        let message_location = location(path, &message);
        let origin_location = location(path, &origin);
        evidence.push(Evidence {
            id: evidence_id(
                path,
                REQUEST_CREDENTIAL_LOGGING_RULE_ID,
                call.range().start,
                call.range().end,
            ),
            kind: EvidenceKind::SensitiveOperation,
            capability: Capability::Logging,
            location: location(path, &call),
            enclosing_symbol: enclosing_symbol(&call),
            captures: BTreeMap::from([
                (
                    "message".to_string(),
                    Capture {
                        text: message.text().into_owned(),
                        location: message_location,
                    },
                ),
                (
                    "credential_origin".to_string(),
                    Capture {
                        text: origin.text().into_owned(),
                        location: origin_location,
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-532".to_string()],
            tags: vec![
                "logging".to_string(),
                "credential".to_string(),
                "request-derived".to_string(),
                "plaintext-value".to_string(),
                "bounded-local-origin".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan bounded-python-credential-logging 1".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&call, literals)),
                availability: Some(conditional.availability_for(call.range())),
                literals: BTreeMap::from([("message".to_string(), literals.evaluate(&message))]),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: REQUEST_CREDENTIAL_LOGGING_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn python_logging_call(callee: &str) -> bool {
    let callee = callee.to_ascii_lowercase();
    if callee == "print" {
        return true;
    }
    let Some((receiver, method)) = callee.rsplit_once('.') else {
        return false;
    };
    let receiver = receiver.rsplit('.').next().unwrap_or(receiver);
    matches!(receiver, "logger" | "log" | "logging" | "_logger")
        && matches!(
            method,
            "debug" | "info" | "warning" | "warn" | "error" | "critical" | "exception" | "log"
        )
}

fn python_logged_credential_origin<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    arguments: &[Node<'tree, StrDoc<SupportLang>>],
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if let Some(argument) = arguments
        .iter()
        .find(|argument| python_direct_request_credential(argument.text().as_ref()))
    {
        return Some(argument.clone());
    }

    let mut credential_origins =
        BTreeMap::<String, (Node<'tree, StrDoc<SupportLang>>, usize)>::new();
    let mut request_containers = BTreeSet::new();
    let mut assignments = function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "assignment"
                && node.range().end < call.range().start
                && node
                    .ancestors()
                    .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
                    .is_some_and(|owner| owner.range() == function.range())
        })
        .collect::<Vec<_>>();
    assignments.sort_by_key(|assignment| assignment.range().start);
    for assignment in assignments {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        if left.kind().as_ref() != "identifier" {
            continue;
        }
        let binding = left.text().into_owned();
        let value = right.text().into_owned();
        credential_origins.remove(&binding);
        request_containers.remove(&binding);

        if python_direct_request_credential(&value) {
            credential_origins.insert(binding, (right, 0));
            continue;
        }
        let identifiers = python_identifier_references(&right);
        if python_request_container(&value) {
            request_containers.insert(binding);
            continue;
        }
        if identifiers
            .iter()
            .any(|identifier| request_containers.contains(identifier))
            && python_sensitive_credential_name(&value)
        {
            credential_origins.insert(binding, (right, 0));
            continue;
        }
        if let Some((origin, depth)) = identifiers
            .iter()
            .filter_map(|identifier| credential_origins.get(identifier))
            .min_by_key(|(_, depth)| *depth)
            .cloned()
            && depth < 2
            && python_preserves_credential_value(&right)
        {
            credential_origins.insert(binding, (origin, depth + 1));
        }
    }

    credential_origins
        .iter()
        .filter(|(binding, _)| {
            arguments
                .iter()
                .any(|argument| python_logs_full_credential_binding(argument, binding))
        })
        .map(|(_, origin)| origin)
        .min_by_key(|(_, depth)| *depth)
        .map(|(origin, _)| origin.clone())
}

fn python_logs_full_credential_binding(
    argument: &Node<'_, StrDoc<SupportLang>>,
    binding: &str,
) -> bool {
    argument.dfs().any(|candidate| {
        if candidate.kind().as_ref() != "identifier" || candidate.text().trim() != binding {
            return false;
        }
        !candidate
            .parent()
            .is_some_and(|parent| python_bounded_prefix_slice(parent.text().trim(), binding))
    })
}

fn python_bounded_prefix_slice(value: &str, binding: &str) -> bool {
    let compact = value.split_whitespace().collect::<String>();
    let Some(length) = compact
        .strip_prefix(&format!("{binding}[:"))
        .and_then(|suffix| suffix.strip_suffix(']'))
        .and_then(|length| length.parse::<usize>().ok())
    else {
        return false;
    };
    length <= 8
}

fn python_preserves_credential_value(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        node.kind().as_ref(),
        "identifier"
            | "dictionary"
            | "list"
            | "tuple"
            | "set"
            | "string"
            | "concatenated_string"
            | "binary_operator"
            | "subscript"
    )
}

fn python_identifier_references(node: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    node.dfs()
        .filter(|candidate| candidate.kind().as_ref() == "identifier")
        .map(|candidate| candidate.text().into_owned())
        .collect()
}

fn python_request_container(value: &str) -> bool {
    let compact = value
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    let compact = compact.strip_prefix("await").unwrap_or(&compact);
    [
        "request.data",
        "request.json",
        "request.get_json(",
        "request.form",
        "request.post",
        "request.body",
    ]
    .iter()
    .any(|origin| compact.starts_with(origin))
}

fn python_direct_request_credential(value: &str) -> bool {
    let compact = value
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase();
    let compact = compact.strip_prefix("await").unwrap_or(&compact);
    [
        "request.meta",
        "request.headers",
        "request.cookies",
        "request.authorization",
        "request.auth",
        "request.data",
        "request.json",
        "request.get_json(",
        "request.form",
        "request.post",
    ]
    .iter()
    .any(|origin| compact.contains(origin))
        && python_sensitive_credential_name(&compact)
}

fn python_sensitive_credential_name(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase().replace('-', "_");
    [
        "authorization",
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "session_key",
        "sessionid",
        "access_key",
        "private_key",
    ]
    .iter()
    .any(|name| normalized.contains(name))
}

fn sensitive_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "available_credit"
            | "balance"
            | "credit"
            | "role"
            | "is_staff"
            | "is_superuser"
            | "owner"
            | "owner_id"
            | "user_id"
            | "account_id"
            | "tenant_id"
            | "status"
            | "approved"
            | "is_approved"
    )
}

fn collect_sensitive_serializer_policies(
    sources: &[(&str, Language, &str)],
) -> BTreeMap<String, Vec<String>> {
    let mut policies = BTreeMap::new();
    for (_, _, source) in sources {
        let lines = source.lines().collect::<Vec<_>>();
        let mut index = 0usize;
        while index < lines.len() {
            let trimmed = lines[index].trim_start();
            let Some(rest) = trimmed.strip_prefix("class ") else {
                index += 1;
                continue;
            };
            let Some((name, bases)) = rest.split_once('(') else {
                index += 1;
                continue;
            };
            if !bases.contains("ModelSerializer") {
                index += 1;
                continue;
            }
            let class_indent = lines[index].len() - trimmed.len();
            let start = index;
            index += 1;
            while index < lines.len() {
                let next = lines[index];
                let next_trimmed = next.trim_start();
                if !next_trimmed.is_empty()
                    && next.len() - next_trimmed.len() <= class_indent
                    && next_trimmed.starts_with("class ")
                {
                    break;
                }
                index += 1;
            }
            let body = lines[start..index].join("\n");
            let fields = serializer_option_strings(&body, "fields");
            let read_only = serializer_option_strings(&body, "read_only_fields")
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mut writable = fields
                .into_iter()
                .filter(|field| sensitive_field(field) && !read_only.contains(field))
                .collect::<Vec<_>>();
            writable.sort();
            writable.dedup();
            if !writable.is_empty() {
                policies.insert(name.trim().to_string(), writable);
            }
        }
    }
    policies
}

fn serializer_option_strings(body: &str, option: &str) -> Vec<String> {
    let Some(start) = body.find(&format!("{option} =")) else {
        return Vec::new();
    };
    let value = &body[start + option.len() + 2..];
    let end = value
        .find("\n        ")
        .or_else(|| value.find("\n    class "))
        .unwrap_or(value.len());
    python_string_literals(&value[..end])
}

#[allow(clippy::too_many_arguments)]
fn push_django_orm_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter(|node| node.kind().as_ref() == "call") {
        let Some(function) = call.field("function") else {
            continue;
        };
        let function_text = function.text();
        let Some((receiver, operation)) = function_text.rsplit_once('.') else {
            continue;
        };
        if !matches!(operation, "get" | "filter" | "update" | "delete")
            || (!receiver.contains(".objects") && !receiver.contains(".using("))
        {
            continue;
        }
        // Chained queryset terminals do not introduce a new selector. The
        // inner get/filter call owns the lookup predicate; update arguments
        // are values to write and must never be reclassified as resource IDs.
        if matches!(operation, "update" | "delete") {
            continue;
        }
        if operation == "filter" && !django_filter_has_resource_terminal(&call) {
            continue;
        }
        let Some((filter, filter_name)) = first_lookup_filter(&call) else {
            continue;
        };
        if django_lookup_is_authentication_credential(&call, &filter_name) {
            continue;
        }
        let owner_basis = django_owner_scope_basis(&call, &filter_name, filter.text().trim());
        let owner_scoped = owner_basis.is_some();
        let rule_id = if owner_scoped {
            ORM_OWNER_CONTROL_RULE_ID
        } else {
            ORM_ACCESS_RULE_ID
        };
        let item_location = location(path, &filter);
        evidence.push(Evidence {
            id: evidence_id(path, rule_id, filter.range().start, filter.range().end),
            kind: if owner_scoped {
                EvidenceKind::Validation
            } else {
                EvidenceKind::Sink
            },
            capability: Capability::ResourceAccess,
            location: item_location.clone(),
            enclosing_symbol: enclosing_symbol(&call),
            captures: BTreeMap::from([
                (
                    "filter".to_string(),
                    Capture {
                        text: filter.text().into_owned(),
                        location: item_location.clone(),
                    },
                ),
                (
                    "model".to_string(),
                    Capture {
                        text: receiver.split('.').next().unwrap_or(receiver).to_string(),
                        location: location(path, &function),
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-639".to_string()],
            tags: vec![
                "django".to_string(),
                "orm".to_string(),
                format!("operation:{operation}"),
                if owner_scoped {
                    "owner-scoped-control"
                } else {
                    "verify-owner-or-tenant-policy"
                }
                .to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan bounded-django-orm-context 1".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(filter.range()),
                reachability: Some(reachability::classify(&filter, literals)),
                availability: Some(conditional.availability_for(filter.range())),
                literals: BTreeMap::from([("filter".to_string(), literals.evaluate(&filter))]),
                resource_policy: Some(ResourcePolicyContext {
                    state: if owner_scoped {
                        ResourcePolicyState::OwnerScoped
                    } else {
                        ResourcePolicyState::Unknown
                    },
                    basis: owner_basis.unwrap_or_else(|| {
                        "lookup key lacks a proved owner, account, or tenant constraint; verify local or framework policy"
                            .to_string()
                    }),
                }),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: rule_id.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn django_filter_has_resource_terminal(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.ancestors().take(4).any(|ancestor| {
        if ancestor.kind().as_ref() != "call" || ancestor.range() == call.range() {
            return false;
        }
        let text = ancestor.text();
        text.contains(".first()")
            || text.contains(".get()")
            || text.contains(".delete()")
            || text.contains(".update(")
    })
}

fn django_lookup_is_authentication_credential(
    call: &Node<'_, StrDoc<SupportLang>>,
    filter_name: &str,
) -> bool {
    let key = filter_name.to_ascii_lowercase();
    if matches!(
        key.as_str(),
        "session" | "session_id" | "session_key" | "token" | "access_token" | "reset_token"
    ) || key.ends_with("__session_id")
        || key.ends_with("__session_key")
        || key.ends_with("__token")
    {
        return true;
    }
    let lookup_arguments = python_call_arguments(call);
    if lookup_arguments.len() >= 2
        && lookup_arguments.iter().any(|argument| {
            argument.kind().as_ref() == "keyword_argument"
                && argument.field("name").is_some_and(|name| {
                    matches!(
                        name.text().trim().to_ascii_lowercase().as_str(),
                        "password" | "password_hash" | "passwd" | "passcode"
                    ) || name
                        .text()
                        .trim()
                        .to_ascii_lowercase()
                        .starts_with("password")
                })
        })
    {
        return true;
    }

    let Some(function) = call
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
    else {
        return false;
    };
    let Some(result_name) = call
        .ancestors()
        .take_while(|ancestor| ancestor.range().start >= function.range().start)
        .find(|ancestor| ancestor.kind().as_ref() == "assignment")
        .and_then(|assignment| assignment.field("left"))
        .filter(|left| left.kind().as_ref() == "identifier")
        .map(|left| left.text().into_owned())
    else {
        return false;
    };

    function.dfs().any(|verify_call| {
        if verify_call.kind().as_ref() != "call" || verify_call.range().start <= call.range().end {
            return false;
        }
        let Some(callee) = verify_call.field("function") else {
            return false;
        };
        let callee = callee.text();
        let Some((hasher, method)) = callee.rsplit_once('.') else {
            return false;
        };
        if method != "verify"
            || !python_call_arguments(&verify_call)
                .first()
                .is_some_and(|argument| argument.text().trim() == format!("{result_name}.password"))
        {
            return false;
        }
        function.dfs().any(|assignment| {
            assignment.kind().as_ref() == "assignment"
                && assignment.range().end <= verify_call.range().start
                && assignment
                    .field("left")
                    .is_some_and(|left| left.text().trim() == hasher)
                && assignment.field("right").is_some_and(|right| {
                    right.kind().as_ref() == "call"
                        && right.field("function").is_some_and(|constructor| {
                            constructor.text().trim().ends_with("PasswordHasher")
                        })
                })
        })
    })
}

fn first_lookup_filter<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    let arguments = python_call_arguments(call);
    for argument in arguments {
        if argument.kind().as_ref() == "keyword_argument" {
            let name = argument.field("name")?.text().into_owned();
            let value = argument.field("value")?;
            return Some((value, name));
        }
        if !matches!(argument.kind().as_ref(), "dictionary_splat" | "list_splat") {
            return Some((argument, "positional".to_string()));
        }
    }
    None
}

fn django_owner_scope_basis(
    call: &Node<'_, StrDoc<SupportLang>>,
    filter_name: &str,
    filter_value: &str,
) -> Option<String> {
    for (name, value) in std::iter::once((filter_name.to_string(), filter_value.to_string())).chain(
        python_call_arguments(call)
            .into_iter()
            .filter(|argument| argument.kind().as_ref() == "keyword_argument")
            .filter_map(|argument| {
                Some((
                    argument.field("name")?.text().into_owned(),
                    argument.field("value")?.text().into_owned(),
                ))
            }),
    ) {
        let key = name.to_ascii_lowercase();
        if ["owner", "user", "account", "tenant"].iter().any(|part| {
            key.split("__")
                .any(|segment| segment == *part || segment == format!("{part}_id"))
        }) && authenticated_identity_value(call, value.trim())
        {
            return Some(format!(
                "ORM predicate `{name}` is constrained by authenticated server-side identity"
            ));
        }
    }
    if let Some(resource) = filter_value.split('.').next()
        && filter_value != resource
        && resource_has_prior_owner_guard(call, resource)
    {
        return Some(format!(
            "ORM predicate `{filter_name}` is derived from `{resource}` after a deny-on-owner-mismatch guard"
        ));
    }
    let function = call
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")?;
    let lookup_name = call
        .ancestors()
        .take_while(|ancestor| ancestor.range().start >= function.range().start)
        .find(|ancestor| ancestor.kind().as_ref() == "assignment")
        .and_then(|assignment| assignment.field("left"))
        .filter(|left| left.kind().as_ref() == "identifier")?
        .text()
        .into_owned();
    for guard in function.dfs().filter(|node| {
        node.kind().as_ref() == "if_statement" && node.range().start > call.range().end
    }) {
        let guard_text = guard.text().into_owned();
        let lower = guard_text.to_ascii_lowercase();
        let compares_resource_identity = guard_text.contains(&format!("{lookup_name}.owner"))
            || guard_text.contains(&format!("{lookup_name}.user"))
            || guard_text.contains(&format!("{lookup_name}.account"))
            || guard_text.contains(&format!("{lookup_name}.tenant"))
            || guard_text.contains(&format!("{lookup_name}.vehicle.owner"));
        let denies = lower.contains("return response")
            && (lower.contains("403") || lower.contains("404") || lower.contains("restricted"))
            || lower.contains("raise permissiondenied")
            || lower.contains("raise notfound");
        if compares_resource_identity
            && denies
            && (guard_text.contains("request.user") || authenticated_identity_value(call, "user"))
        {
            return Some(format!(
                "a following deny-on-mismatch guard compares `{lookup_name}` ownership with authenticated identity"
            ));
        }
    }
    None
}

fn resource_has_prior_owner_guard(call: &Node<'_, StrDoc<SupportLang>>, resource: &str) -> bool {
    let Some(function) = call
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
    else {
        return false;
    };
    let assigned_before = function.dfs().any(|node| {
        node.kind().as_ref() == "assignment"
            && node.range().start < call.range().start
            && node
                .field("left")
                .is_some_and(|left| left.text().trim() == resource)
            && node.field("right").is_some_and(|right| {
                let text = right.text();
                text.contains(".objects.get(") || text.contains(".objects.filter(")
            })
    });
    assigned_before
        && function.dfs().any(|guard| {
            if guard.kind().as_ref() != "if_statement" || guard.range().end > call.range().start {
                return false;
            }
            let text = guard.text().into_owned();
            let lower = text.to_ascii_lowercase();
            let compares_owner = text.contains(&format!("{resource}.owner"))
                || text.contains(&format!("{resource}.user"))
                || text.contains(&format!("{resource}.account"))
                || text.contains(&format!("{resource}.tenant"));
            compares_owner
                && (text.contains("request.user") || authenticated_identity_value(call, "user"))
                && ((lower.contains("return response")
                    && (lower.contains("403")
                        || lower.contains("404")
                        || lower.contains("restricted")))
                    || lower.contains("raise permissiondenied")
                    || lower.contains("raise notfound"))
        })
}

fn authenticated_identity_value(call: &Node<'_, StrDoc<SupportLang>>, value: &str) -> bool {
    if value.contains("request.user") {
        return true;
    }
    if value.trim() != "user" {
        return false;
    }
    call.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
        .is_some_and(|function| {
            matches!(
                handler_access(&function, enclosing_python_class(&function).as_deref()).0,
                HttpRouteAccess::Authenticated | HttpRouteAccess::RoleRestricted
            )
        })
}

#[allow(clippy::too_many_arguments)]
fn push_sensitive_field_mutations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for assignment in root
        .dfs()
        .filter(|node| matches!(node.kind().as_ref(), "assignment" | "augmented_assignment"))
    {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left_text = left.text().into_owned();
        let Some((receiver, field)) = left_text.rsplit_once('.') else {
            continue;
        };
        if !sensitive_field(field)
            || !python_value_is_request_controlled(&assignment, right.text().trim())
        {
            continue;
        }
        let Some(function) = assignment
            .ancestors()
            .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        if !function.dfs().any(|node| {
            node.kind().as_ref() == "call"
                && node.range().start > assignment.range().end
                && node.field("function").is_some_and(|callee| {
                    let text = callee.text();
                    text.trim() == format!("{receiver}.save")
                })
        }) {
            continue;
        }
        let validation = nearby_rejecting_mutation_validation(&assignment, &left, &right);
        push_sensitive_write_evidence(
            path,
            &right,
            validation.as_ref(),
            SENSITIVE_MUTATION_RULE_ID,
            vec![field.to_string()],
            "direct-model-field-assignment",
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn python_value_is_request_controlled(node: &Node<'_, StrDoc<SupportLang>>, value: &str) -> bool {
    if value.contains("request.data")
        || value.contains("request.POST")
        || value.contains("request.GET")
        || value.contains("request.query_params")
    {
        return true;
    }
    let identifiers = value
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|identifier| !identifier.is_empty())
        .collect::<BTreeSet<_>>();
    if identifiers.is_empty() {
        return false;
    }
    let Some(function) = node
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
    else {
        return false;
    };
    function.dfs().any(|candidate| {
        candidate.kind().as_ref() == "assignment"
            && candidate.range().end < node.range().start
            && candidate
                .field("left")
                .is_some_and(|left| identifiers.contains(left.text().trim()))
            && candidate.field("right").is_some_and(|right| {
                let text = right.text();
                text.contains("request.data")
                    || text.contains("request.POST")
                    || text.contains("request.GET")
                    || text.contains("request.query_params")
            })
    })
}

#[allow(clippy::too_many_arguments)]
fn push_sensitive_serializer_writes<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    policies: &BTreeMap<String, Vec<String>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment")
    {
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        if left.kind().as_ref() != "identifier" || right.kind().as_ref() != "call" {
            continue;
        }
        let Some(serializer) = right.field("function").map(|node| node.text().into_owned()) else {
            continue;
        };
        let Some(fields) = policies.get(&serializer) else {
            continue;
        };
        let Some(input) = python_call_arguments(&right)
            .into_iter()
            .find_map(|argument| {
                (argument.kind().as_ref() == "keyword_argument"
                    && argument
                        .field("name")
                        .is_some_and(|name| name.text().trim() == "data"))
                .then(|| argument.field("value"))
                .flatten()
            })
        else {
            continue;
        };
        if !python_value_is_request_controlled(&assignment, input.text().trim()) {
            continue;
        }
        let binding = left.text().into_owned();
        let persisted = assignment
            .ancestors()
            .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
            .is_some_and(|function| {
                function.dfs().any(|node| {
                    node.kind().as_ref() == "call"
                        && node.range().start > assignment.range().end
                        && node
                            .field("function")
                            .is_some_and(|callee| callee.text().trim() == format!("{binding}.save"))
                })
            });
        if persisted {
            push_sensitive_write_evidence(
                path,
                &input,
                None,
                SERIALIZER_WRITE_RULE_ID,
                fields.clone(),
                "model-serializer-writable-field-policy",
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_sensitive_write_evidence<'tree>(
    path: &str,
    input: &Node<'tree, StrDoc<SupportLang>>,
    validation: Option<&Node<'tree, StrDoc<SupportLang>>>,
    rule_id: &str,
    fields: Vec<String>,
    basis: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let item_location = location(path, input);
    let mut captures = BTreeMap::from([(
        "assigned_fields".to_string(),
        Capture {
            text: input.text().into_owned(),
            location: item_location.clone(),
        },
    )]);
    if let Some(validation) = validation {
        captures.insert(
            "nearby_rejecting_validation".to_string(),
            Capture {
                text: validation.text().into_owned(),
                location: location(path, validation),
            },
        );
    }
    evidence.push(Evidence {
        id: evidence_id(path, rule_id, input.range().start, input.range().end),
        kind: EvidenceKind::Sink,
        capability: Capability::ResourceAccess,
        location: item_location.clone(),
        enclosing_symbol: enclosing_symbol(input),
        captures,
        cwe_candidates: vec!["CWE-915".to_string()],
        tags: std::iter::once("django".to_string())
            .chain(std::iter::once("sensitive-model-write".to_string()))
            .chain(std::iter::once(format!("basis:{basis}")))
            .chain(
                validation
                    .is_some()
                    .then_some("nearby-rejecting-validation".to_string()),
            )
            .chain(fields.into_iter().map(|field| format!("field:{field}")))
            .collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: "mehscan bounded-django-sensitive-write 1".to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(input.range()),
            reachability: Some(reachability::classify(input, literals)),
            availability: Some(conditional.availability_for(input.range())),
            literals: std::iter::once(("assigned_fields".to_string(), literals.evaluate(input)))
                .chain(validation.map(|validation| {
                    (
                        "nearby_rejecting_validation".to_string(),
                        literals.evaluate(validation),
                    )
                }))
                .collect(),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    });
}

fn nearby_rejecting_mutation_validation<'tree>(
    assignment: &Node<'tree, StrDoc<SupportLang>>,
    left: &Node<'tree, StrDoc<SupportLang>>,
    right: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let function = assignment
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")?;
    let left = left.text().into_owned();
    let right_terms = right
        .dfs()
        .filter(|node| matches!(node.kind().as_ref(), "attribute" | "subscript"))
        .map(|node| node.text().into_owned())
        .filter(|term| term.len() >= 4)
        .collect::<BTreeSet<_>>();
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "if_statement"
                && node.range().end < assignment.range().start
                && assignment
                    .start_pos()
                    .line()
                    .saturating_sub(node.end_pos().line())
                    <= 40
                && node
                    .ancestors()
                    .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
                    .is_some_and(|owner| owner.range() == function.range())
        })
        .filter_map(|statement| {
            let condition = statement.field("condition")?;
            let consequence = statement.field("consequence")?;
            if !consequence
                .dfs()
                .any(|node| matches!(node.kind().as_ref(), "return_statement" | "raise_statement"))
            {
                return None;
            }
            let condition_text = condition.text();
            (condition_text.contains(left.as_str())
                || right_terms
                    .iter()
                    .any(|term| condition_text.contains(term.as_str())))
            .then_some(condition)
        })
        .max_by_key(|condition| condition.range().start)
}

fn django_template_name(path: &str) -> Option<String> {
    let normalized = path.replace('\\', "/");
    normalized.strip_prefix("templates/").map_or_else(
        || {
            normalized
                .rsplit_once("/templates/")
                .map(|(_, suffix)| suffix.to_string())
        },
        |suffix| Some(suffix.to_string()),
    )
}

fn unsafe_django_template_bindings(source: &str) -> BTreeMap<String, String> {
    let mut bindings = BTreeMap::new();
    let mut loop_bindings = BTreeMap::new();
    for fragment in source.split("{% for ").skip(1) {
        let Some(header) = fragment.split("%}").next() else {
            continue;
        };
        if let Some((item, collection)) = header.split_once(" in ") {
            loop_bindings.insert(item.trim(), collection.trim());
        }
    }
    let mut offset = 0usize;
    while let Some(relative_start) = source[offset..].find("{{") {
        let start = offset + relative_start;
        let Some(relative_end) = source[start + 2..].find("}}") else {
            break;
        };
        let end = start + 2 + relative_end;
        let expression = source[start + 2..end].trim();
        let variable = expression
            .split('|')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let root = variable.split('.').next().unwrap_or(variable);
        let binding = loop_bindings.get(root).copied().unwrap_or(root);
        if binding
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            && !binding.is_empty()
        {
            let has_safe_filter = expression
                .split('|')
                .skip(1)
                .map(|filter| filter.split(':').next().unwrap_or_default().trim())
                .any(|filter| filter == "safe");
            let before = source[..start].to_ascii_lowercase();
            let inside_script = before
                .rfind("<script")
                .is_some_and(|open| before.rfind("</script>").is_none_or(|close| close < open));
            if has_safe_filter {
                bindings.insert(binding.to_string(), format!("{{{{ {expression} }}}}:safe"));
            } else if inside_script {
                bindings.insert(
                    binding.to_string(),
                    format!("{{{{ {expression} }}}}:javascript-context"),
                );
            }
        }
        offset = end + 2;
    }
    bindings
}

#[allow(clippy::too_many_arguments)]
fn push_unsafe_template_outputs<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    templates: &BTreeMap<String, BTreeMap<String, String>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter(|node| {
        node.kind().as_ref() == "call"
            && node.field("function").is_some_and(|function| {
                matches!(function.text().trim(), "render" | "render_template")
            })
    }) {
        let arguments = python_call_arguments(&call);
        let is_flask = call
            .field("function")
            .is_some_and(|function| function.text().trim() == "render_template");
        let rule_id = if is_flask {
            FLASK_TEMPLATE_OUTPUT_RULE_ID
        } else {
            TEMPLATE_OUTPUT_RULE_ID
        };
        let Some(template_name) = arguments
            .get(if is_flask { 0 } else { 1 })
            .and_then(|argument| python_string_literal(argument.text().trim()))
        else {
            continue;
        };
        let Some(unsafe_bindings) = templates.get(&template_name) else {
            continue;
        };
        let mut values = Vec::new();
        if is_flask {
            for argument in arguments.iter().skip(1) {
                if argument.kind().as_ref() != "keyword_argument" {
                    continue;
                }
                if let (Some(key), Some(value)) = (argument.field("name"), argument.field("value"))
                {
                    values.push((key.text().into_owned(), value));
                }
            }
        } else if let Some(context) = arguments
            .get(2)
            .and_then(|argument| resolve_python_dictionary(&call, argument))
        {
            for pair in context
                .children()
                .filter(|child| child.kind().as_ref() == "pair")
            {
                let (Some(key), Some(value)) = (pair.field("key"), pair.field("value")) else {
                    continue;
                };
                if let Some(key) = python_string_literal(key.text().trim()) {
                    values.push((key, value));
                }
            }
        };
        for (key, value) in values {
            if matches!(
                value.kind().as_ref(),
                "string" | "concatenated_string" | "integer" | "float" | "true" | "false" | "none"
            ) {
                continue;
            }
            let Some(template_expression) = unsafe_bindings.get(&key) else {
                continue;
            };
            let location = location(path, &value);
            evidence.push(Evidence {
                id: evidence_id(path, rule_id, value.range().start, value.range().end),
                kind: EvidenceKind::Sink,
                capability: Capability::HtmlOutput,
                location: location.clone(),
                enclosing_symbol: enclosing_symbol(&call),
                captures: BTreeMap::from([
                    (
                        "content".to_string(),
                        Capture {
                            text: value.text().into_owned(),
                            location: location.clone(),
                        },
                    ),
                    (
                        "template".to_string(),
                        Capture {
                            text: template_name.clone(),
                            location: location.clone(),
                        },
                    ),
                    (
                        "template_expression".to_string(),
                        Capture {
                            text: template_expression.clone(),
                            location: location.clone(),
                        },
                    ),
                ]),
                cwe_candidates: vec!["CWE-79".to_string()],
                tags: vec![
                    "django".to_string(),
                    "template".to_string(),
                    "unsafe-output-context".to_string(),
                ],
                confidence: if template_expression.ends_with(":safe") {
                    Confidence::High
                } else {
                    Confidence::Medium
                },
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "mehscan python-django-template-context 1".to_string(),
                    rule_version: 1,
                },
                context: EvidenceContext {
                    comment: comments.is_in_comment(value.range()),
                    reachability: Some(reachability::classify(&value, literals)),
                    availability: Some(conditional.availability_for(value.range())),
                    ..EvidenceContext::default()
                },
                symbol_resolution: None,
                rule_id: rule_id.to_string(),
                related_evidence: Vec::new(),
            });
        }
    }
}

fn resolve_python_dictionary<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    argument: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if argument.kind().as_ref() == "dictionary" {
        return Some(argument.clone());
    }
    let binding = argument.text();
    let binding = binding.trim();
    if binding.is_empty()
        || !binding
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return None;
    }
    let function = call
        .ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")?;
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "assignment" && node.range().end < call.range().start
        })
        .filter_map(|assignment| {
            let left = assignment.field("left")?;
            let right = assignment.field("right")?;
            (left.text().trim() == binding && right.kind().as_ref() == "dictionary")
                .then_some(right)
        })
        .max_by_key(|dictionary| dictionary.range().start)
}

fn python_call_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.children()
        .find(|child| child.kind().as_ref() == "argument_list")
        .map(|arguments| {
            arguments
                .children()
                .filter(|argument| !matches!(argument.kind().as_ref(), "(" | ")" | ","))
                .collect()
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn push_python_source_file_content_writes<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for function in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_definition")
    {
        let function_range = function.range();
        let assignments = function
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "assignment"
                    && nearest_python_function_range(node).as_ref() == Some(&function_range)
            })
            .collect::<Vec<_>>();

        for open_assignment in &assignments {
            let (Some(handle), Some(open_call)) = (
                open_assignment.field("left"),
                open_assignment.field("right"),
            ) else {
                continue;
            };
            let handle_name = handle.text();
            let handle_name = handle_name.trim();
            if simple_identifier(handle_name).is_none()
                || open_call.kind().as_ref() != "call"
                || open_call
                    .field("function")
                    .is_none_or(|callee| callee.text().trim() != "open")
            {
                continue;
            }
            let open_arguments = python_call_arguments(&open_call);
            let Some(path_argument) = open_arguments.first() else {
                continue;
            };
            if !python_open_has_write_mode(&open_arguments)
                || !python_path_is_source_file(
                    path_argument,
                    &assignments,
                    open_assignment.range().start,
                )
            {
                continue;
            }

            for write_call in function.dfs().filter(|node| {
                node.kind().as_ref() == "call"
                    && open_assignment.range().end <= node.range().start
                    && nearest_python_function_range(node).as_ref() == Some(&function_range)
                    && node.field("function").is_some_and(|callee| {
                        callee.text().trim() == format!("{handle_name}.write")
                    })
            }) {
                if assignments.iter().any(|assignment| {
                    open_assignment.range().end <= assignment.range().start
                        && assignment.range().end <= write_call.range().start
                        && assignment
                            .field("left")
                            .is_some_and(|left| left.text().trim() == handle_name)
                }) {
                    continue;
                }
                let write_arguments = python_call_arguments(&write_call);
                let Some(content) = write_arguments.first() else {
                    continue;
                };
                let content_location = location(path, content);
                evidence.push(Evidence {
                    id: evidence_id(
                        path,
                        SOURCE_FILE_CONTENT_WRITE_RULE_ID,
                        content.range().start,
                        content.range().end,
                    ),
                    kind: EvidenceKind::Sink,
                    capability: Capability::FilesystemWrite,
                    location: content_location.clone(),
                    enclosing_symbol: enclosing_symbol(&write_call),
                    captures: BTreeMap::from([
                        (
                            "content".to_string(),
                            Capture {
                                text: content.text().into_owned(),
                                location: content_location.clone(),
                            },
                        ),
                        (
                            "path".to_string(),
                            Capture {
                                text: path_argument.text().into_owned(),
                                location: location(path, path_argument),
                            },
                        ),
                    ]),
                    cwe_candidates: vec!["CWE-94".to_string()],
                    tags: vec![
                        "python".to_string(),
                        "filesystem".to_string(),
                        "source-file".to_string(),
                        "content-write".to_string(),
                        "code-injection-review".to_string(),
                    ],
                    confidence: Confidence::High,
                    provenance: Provenance {
                        resolution: Resolution::Ast,
                        engine: "mehscan bounded-python-source-file-write 1".to_string(),
                        rule_version: 1,
                    },
                    context: EvidenceContext {
                        comment: comments.is_in_comment(content.range()),
                        reachability: Some(reachability::classify(content, literals)),
                        availability: Some(conditional.availability_for(content.range())),
                        ..EvidenceContext::default()
                    },
                    symbol_resolution: None,
                    rule_id: SOURCE_FILE_CONTENT_WRITE_RULE_ID.to_string(),
                    related_evidence: Vec::new(),
                });
            }
        }
    }
}

fn nearest_python_function_range(
    node: &Node<'_, StrDoc<SupportLang>>,
) -> Option<std::ops::Range<usize>> {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
        .map(|function| function.range())
}

fn python_open_has_write_mode(arguments: &[Node<'_, StrDoc<SupportLang>>]) -> bool {
    let mode = arguments
        .get(1)
        .filter(|argument| argument.kind().as_ref() != "keyword_argument")
        .cloned()
        .or_else(|| {
            arguments.iter().find_map(|argument| {
                (argument.kind().as_ref() == "keyword_argument"
                    && argument
                        .field("name")
                        .is_some_and(|name| name.text().trim() == "mode"))
                .then(|| argument.field("value"))
                .flatten()
            })
        });
    mode.is_some_and(|mode| {
        matches!(
            python_plain_string_literal(mode.text().trim()),
            Some("w" | "wb" | "a" | "ab")
        )
    })
}

fn python_path_is_source_file(
    path_argument: &Node<'_, StrDoc<SupportLang>>,
    assignments: &[Node<'_, StrDoc<SupportLang>>],
    before: usize,
) -> bool {
    if python_expression_has_source_file_literal(path_argument) {
        return true;
    }
    let path_name = path_argument.text();
    let path_name = path_name.trim();
    if simple_identifier(path_name).is_none() {
        return false;
    }
    assignments
        .iter()
        .filter(|assignment| assignment.range().end <= before)
        .filter_map(|assignment| {
            let left = assignment.field("left")?;
            let right = assignment.field("right")?;
            (left.text().trim() == path_name).then_some(right)
        })
        .max_by_key(|right| right.range().start)
        .is_some_and(|right| python_expression_has_source_file_literal(&right))
}

fn python_expression_has_source_file_literal(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.dfs().any(|candidate| {
        candidate.kind().as_ref() == "string"
            && python_plain_string_literal(candidate.text().trim())
                .is_some_and(|value| value.to_ascii_lowercase().ends_with(".py"))
    })
}

fn python_plain_string_literal(text: &str) -> Option<&str> {
    let text = text.trim();
    let quote = text.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'\"') || text.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    text.get(1..text.len().checked_sub(1)?)
}

fn simple_identifier(text: &str) -> Option<&str> {
    (!text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && !text.as_bytes()[0].is_ascii_digit())
    .then_some(text)
}

#[derive(Clone, Debug)]
struct PythonParameterSinkSummary {
    name: String,
    parameter_index: usize,
    capability: Capability,
    capture_role: &'static str,
    cwe: &'static str,
    helper_start: usize,
    helper_end: usize,
}

#[allow(clippy::too_many_arguments)]
fn push_file_local_parameter_sink_summaries<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let functions = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_definition")
        .collect::<Vec<_>>();
    let name_counts = functions
        .iter()
        .fold(BTreeMap::new(), |mut counts, function| {
            if let Some(name) = function.field("name") {
                *counts.entry(name.text().into_owned()).or_insert(0usize) += 1;
            }
            counts
        });
    let mut summaries = Vec::new();
    for function in &functions {
        let Some(name) = function.field("name").map(|node| node.text().into_owned()) else {
            continue;
        };
        if name_counts.get(&name) != Some(&1) {
            continue;
        }
        let Some(parameters) = function.field("parameters") else {
            continue;
        };
        let parameters = parameters
            .children()
            .filter_map(parameter_name_node)
            .map(|parameter| parameter.text().into_owned())
            .collect::<Vec<_>>();
        let candidates = evidence
            .iter()
            .filter(|item| {
                item.location.path == path
                    && item.kind == EvidenceKind::Sink
                    && matches!(
                        item.capability,
                        Capability::ProcessExecution
                            | Capability::FilesystemRead
                            | Capability::FilesystemWrite
                            | Capability::OutboundNetworkRequest
                    )
                    && item.location.start.byte_offset >= function.range().start
                    && item.location.end.byte_offset <= function.range().end
            })
            .filter_map(|sink| {
                let (capture_role, cwe) = match sink.capability {
                    Capability::ProcessExecution => ("command", "CWE-78"),
                    Capability::FilesystemRead | Capability::FilesystemWrite => ("path", "CWE-22"),
                    Capability::OutboundNetworkRequest => ("endpoint", "CWE-918"),
                    _ => return None,
                };
                let captured = sink.captures.get(capture_role)?.text.trim();
                let captured = if sink.capability == Capability::OutboundNetworkRequest {
                    captured
                        .split_once('=')
                        .filter(|(name, _)| matches!(name.trim(), "url" | "uri" | "endpoint"))
                        .map(|(_, value)| value.trim())
                        .unwrap_or(captured)
                } else {
                    captured
                };
                let parameter_index = parameters
                    .iter()
                    .position(|parameter| parameter == captured)?;
                Some((parameter_index, sink.capability, capture_role, cwe))
            })
            .collect::<BTreeSet<_>>();
        if candidates.len() != 1 {
            continue;
        }
        let (parameter_index, capability, capture_role, cwe) =
            *candidates.first().expect("one candidate");
        summaries.push(PythonParameterSinkSummary {
            name,
            parameter_index,
            capability,
            capture_role,
            cwe,
            helper_start: function.range().start,
            helper_end: function.range().end,
        });
    }

    for summary in summaries {
        for call in root.dfs().filter(|node| {
            node.kind().as_ref() == "call"
                && node
                    .field("function")
                    .is_some_and(|function| function.text().trim() == summary.name)
                && !(summary.helper_start <= node.range().start
                    && node.range().end <= summary.helper_end)
        }) {
            let arguments = python_call_arguments(&call);
            let Some(command) = arguments.get(summary.parameter_index) else {
                continue;
            };
            let location = location(path, command);
            evidence.push(Evidence {
                id: evidence_id(
                    path,
                    PARAMETER_SINK_RULE_ID,
                    command.range().start,
                    command.range().end,
                ),
                kind: EvidenceKind::Sink,
                capability: summary.capability,
                location: location.clone(),
                enclosing_symbol: enclosing_symbol(&call),
                captures: BTreeMap::from([
                    (
                        summary.capture_role.to_string(),
                        Capture {
                            text: command.text().into_owned(),
                            location: location.clone(),
                        },
                    ),
                    (
                        "helper".to_string(),
                        Capture {
                            text: summary.name.clone(),
                            location: location.clone(),
                        },
                    ),
                ]),
                cwe_candidates: vec![summary.cwe.to_string()],
                tags: vec![
                    "python".to_string(),
                    capability_tag(summary.capability).to_string(),
                    "file-local".to_string(),
                    "unique-helper-summary".to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: Provenance {
                    resolution: Resolution::Ast,
                    engine: "mehscan bounded-python-parameter-sink-summary 1".to_string(),
                    rule_version: 1,
                },
                context: EvidenceContext {
                    comment: comments.is_in_comment(command.range()),
                    reachability: Some(reachability::classify(command, literals)),
                    availability: Some(conditional.availability_for(command.range())),
                    ..EvidenceContext::default()
                },
                symbol_resolution: None,
                rule_id: PARAMETER_SINK_RULE_ID.to_string(),
                related_evidence: Vec::new(),
            });
        }
    }
}

fn capability_tag(capability: Capability) -> &'static str {
    match capability {
        Capability::ProcessExecution => "process",
        Capability::FilesystemRead | Capability::FilesystemWrite => "filesystem",
        Capability::OutboundNetworkRequest => "outbound-request",
        _ => "security-sink",
    }
}

#[allow(clippy::too_many_arguments)]
fn push_csrf_exempt_context<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    routes: &[HttpRouteContext],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(decorated) = function
        .parent()
        .filter(|parent| parent.kind().as_ref() == "decorated_definition")
    else {
        return;
    };
    for decorator in decorated.children().filter(|child| {
        child.kind().as_ref() == "decorator"
            && child
                .text()
                .chars()
                .filter(|character| !character.is_whitespace() && *character != '@')
                .collect::<String>()
                .trim_end_matches("()")
                .ends_with("csrf_exempt")
    }) {
        let location = location(path, &decorator);
        evidence.push(Evidence {
            id: evidence_id(
                path,
                CSRF_EXEMPT_RULE_ID,
                decorator.range().start,
                decorator.range().end,
            ),
            kind: EvidenceKind::SecurityConfiguration,
            capability: Capability::HttpRequestHandling,
            location: location.clone(),
            // `enclosing_symbol` intentionally starts at ancestors, which is
            // correct for observations inside a function but not for a
            // decorator attached to the function itself. Preserve the exact
            // handler name so review admission can inspect only this handler.
            enclosing_symbol: function
                .field("name")
                .map(|name| name.text().into_owned())
                .or_else(|| enclosing_symbol(function)),
            captures: BTreeMap::from([(
                "policy".to_string(),
                Capture {
                    text: decorator.text().into_owned(),
                    location,
                },
            )]),
            cwe_candidates: vec!["CWE-352".to_string()],
            tags: vec![
                "csrf".to_string(),
                "django".to_string(),
                "exempt".to_string(),
                "review".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan python-django-csrf-context 1".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(decorator.range()),
                reachability: Some(reachability::classify(&decorator, literals)),
                availability: Some(conditional.availability_for(decorator.range())),
                http_routes: routes.to_vec(),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: CSRF_EXEMPT_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn push_disabled_tls_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for keyword in root.dfs().filter(|node| {
        node.kind().as_ref() == "keyword_argument"
            && node
                .text()
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                == "verify=False"
    }) {
        let Some(call) = keyword.ancestors().find(|ancestor| {
            ancestor.kind().as_ref() == "call"
                && ancestor
                    .field("function")
                    .is_some_and(|function| is_tls_http_call(function.text().trim()))
        }) else {
            continue;
        };
        let location = location(path, &keyword);
        evidence.push(Evidence {
            id: evidence_id(
                path,
                TLS_DISABLED_RULE_ID,
                keyword.range().start,
                keyword.range().end,
            ),
            kind: EvidenceKind::SecurityConfiguration,
            capability: Capability::TlsConfiguration,
            location: location.clone(),
            enclosing_symbol: enclosing_symbol(&call),
            captures: BTreeMap::from([
                (
                    "verification".to_string(),
                    Capture {
                        text: "False".to_string(),
                        location: location.clone(),
                    },
                ),
                (
                    "operation".to_string(),
                    Capture {
                        text: call
                            .field("function")
                            .map_or_else(String::new, |function| function.text().into_owned()),
                        location: location.clone(),
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-295".to_string()],
            tags: vec![
                "tls".to_string(),
                "certificate-validation".to_string(),
                "python".to_string(),
                "review".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "mehscan python-http-tls-context 1".to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(keyword.range()),
                reachability: Some(reachability::classify(&keyword, literals)),
                availability: Some(conditional.availability_for(keyword.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: TLS_DISABLED_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn is_tls_http_call(function: &str) -> bool {
    let compact = function
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    matches!(
        compact.as_str(),
        "requests.get"
            | "requests.post"
            | "requests.put"
            | "requests.patch"
            | "requests.delete"
            | "requests.head"
            | "requests.options"
            | "requests.request"
            | "httpx.get"
            | "httpx.post"
            | "httpx.put"
            | "httpx.patch"
            | "httpx.delete"
            | "httpx.head"
            | "httpx.options"
            | "httpx.request"
            | "httpx.Client"
            | "httpx.AsyncClient"
    )
}

fn declared_handler_keys(path: &str, source: &str) -> Vec<String> {
    let module = module_from_path(path);
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let name = trimmed
                .strip_prefix("class ")
                .or_else(|| trimmed.strip_prefix("def "))?
                .split(['(', ':'])
                .next()?
                .trim();
            (!name.is_empty()).then(|| format!("{module}:{name}"))
        })
        .collect()
}

fn collect_registrations(
    path: &str,
    source: &str,
    declared: &BTreeSet<String>,
) -> Vec<Registration> {
    if !path.replace('\\', "/").ends_with("urls.py") {
        return Vec::new();
    }
    let module = module_from_path(path);
    let aliases = python_import_aliases(source);
    let mut result = Vec::new();
    for call in extract_named_calls(source, &["path", "re_path"]) {
        let arguments = split_top_level_arguments(call);
        if arguments.len() < 2 {
            continue;
        }
        let Some(route) = python_string_literal(arguments[0]) else {
            continue;
        };
        let target = arguments[1].trim();
        if let Some(include) = strip_call(target, "include")
            .and_then(|arguments| split_top_level_arguments(arguments).first().copied())
            .and_then(python_string_literal)
        {
            result.push(Registration {
                module: module.clone(),
                path: route,
                target: RegistrationTarget::Include(include),
            });
            continue;
        }
        let target = target.strip_suffix(".as_view()").unwrap_or(target);
        let segments = target.split('.').collect::<Vec<_>>();
        let Some(name) = segments.last().copied().filter(|value| !value.is_empty()) else {
            continue;
        };
        let mut target_module = if segments.len() > 1 {
            let prefix = segments[..segments.len() - 1].join(".");
            aliases.get(&prefix).cloned().unwrap_or(prefix)
        } else {
            module.clone()
        };
        if let Some(imported) = aliases.get(name)
            && let Some((parent, imported_name)) = imported.rsplit_once('.')
        {
            target_module = parent.to_string();
            if imported_name != name {
                continue;
            }
        }
        let exact = format!("{target_module}:{name}");
        let handler = if declared.contains(&exact) {
            exact
        } else {
            let candidates = declared
                .iter()
                .filter(|key| key.ends_with(&format!(":{name}")))
                .cloned()
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                continue;
            }
            candidates[0].clone()
        };
        result.push(Registration {
            module: module.clone(),
            path: route,
            target: RegistrationTarget::Handler(handler),
        });
    }
    result
}

fn python_import_aliases(source: &str) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for line in source.lines().map(str::trim) {
        if let Some(imported) = line.strip_prefix("import ") {
            for item in imported.split(',') {
                let pieces = item.split_whitespace().collect::<Vec<_>>();
                match pieces.as_slice() {
                    [module, "as", alias] => {
                        aliases.insert((*alias).to_string(), (*module).to_string());
                    }
                    [module] => {
                        aliases.insert((*module).to_string(), (*module).to_string());
                    }
                    _ => {}
                }
            }
        } else if let Some(rest) = line.strip_prefix("from ")
            && let Some((module, imported)) = rest.split_once(" import ")
        {
            for item in imported.split(',') {
                let pieces = item.split_whitespace().collect::<Vec<_>>();
                match pieces.as_slice() {
                    [name, "as", alias] => {
                        aliases.insert((*alias).to_string(), format!("{module}.{name}"));
                    }
                    [name] => {
                        aliases.insert((*name).to_string(), format!("{module}.{name}"));
                    }
                    _ => {}
                }
            }
        }
    }
    aliases
}

fn extract_named_calls<'a>(source: &'a str, names: &[&str]) -> Vec<&'a str> {
    let bytes = source.as_bytes();
    let mut calls = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let Some((name, start)) = names
            .iter()
            .filter_map(|name| {
                source[index..]
                    .find(&format!("{name}("))
                    .map(|offset| (*name, index + offset))
            })
            .min_by_key(|(_, start)| *start)
        else {
            break;
        };
        if start > 0 {
            let previous = bytes[start - 1];
            if previous.is_ascii_alphanumeric() || previous == b'_' || previous == b'.' {
                index = start + name.len();
                continue;
            }
        }
        let open = start + name.len();
        let mut depth = 0usize;
        let mut quote = None;
        let mut escaped = false;
        let mut end = None;
        for (offset, byte) in bytes[open..].iter().copied().enumerate() {
            if let Some(active) = quote {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == active {
                    quote = None;
                }
                continue;
            }
            match byte {
                b'\'' | b'"' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(open + offset);
                        break;
                    }
                }
                _ => {}
            }
        }
        if let Some(end) = end {
            calls.push(&source[open + 1..end]);
            index = end + 1;
        } else {
            break;
        }
    }
    calls
}

fn split_top_level_arguments(arguments: &str) -> Vec<&str> {
    let bytes = arguments.as_bytes();
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote = None;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                result.push(arguments[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if start < arguments.len() {
        result.push(arguments[start..].trim());
    }
    result
}

fn strip_call<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.trim()
        .strip_prefix(&format!("{name}("))?
        .strip_suffix(')')
}

fn python_string_literal(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let quote_start = trimmed.find(['\'', '"'])?;
    let quote = trimmed.as_bytes()[quote_start];
    let body = &trimmed[quote_start + 1..];
    let quote_end = body.rfind(char::from(quote))?;
    Some(body[..quote_end].to_string())
}

fn module_from_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_end_matches(".py")
        .trim_end_matches("/__init__")
        .replace('/', ".")
}

fn join_route(prefix: &str, path: &str) -> String {
    let left = prefix.trim_matches(['^', '$', '/']);
    let right = path.trim_matches(['^', '$', '/']);
    match (left.is_empty(), right.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{right}"),
        (false, true) => format!("/{left}"),
        (false, false) => format!("/{left}/{right}"),
    }
}

fn enclosing_python_class(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind().as_ref() == "class_definition" {
            return parent.field("name").map(|name| name.text().into_owned());
        }
        current = parent.parent();
    }
    None
}

fn handler_access(
    function: &Node<'_, StrDoc<SupportLang>>,
    class_name: Option<&str>,
) -> (HttpRouteAccess, Vec<String>) {
    let mut text = function.text().into_owned();
    if let Some(parent) = function.parent()
        && parent.kind().as_ref() == "decorated_definition"
    {
        text = parent.text().into_owned();
    }
    if class_name.is_some()
        && let Some(class) = enclosing_class_node(function)
        && let Some(body) = class.field("body")
    {
        for child in body.children().filter(|child| {
            !matches!(
                child.kind().as_ref(),
                "function_definition" | "decorated_definition"
            )
        }) {
            let child_text = child.text();
            if child_text.contains("permission_classes")
                || child_text.contains("authentication_classes")
            {
                text.push_str(child_text.as_ref());
            }
        }
    }
    let mut guards = Vec::new();
    for guard in [
        "jwt_auth_required",
        "login_required",
        "permission_required",
        "authentication_classes",
        "permission_classes",
        "IsAuthenticated",
        "IsAdminUser",
        "AllowAny",
    ] {
        if text.contains(guard) {
            guards.push(guard.to_string());
        }
    }
    let access = if guards.iter().any(|guard| guard == "AllowAny") {
        HttpRouteAccess::ExplicitlyPublic
    } else if guards.iter().any(|guard| guard == "IsAdminUser") {
        HttpRouteAccess::RoleRestricted
    } else if guards.iter().any(|guard| guard == "IsAuthenticated") {
        HttpRouteAccess::Authenticated
    } else {
        HttpRouteAccess::Unknown
    };
    guards.sort();
    guards.dedup();
    (access, guards)
}

fn http_method(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "get" => Some("GET"),
        "post" => Some("POST"),
        "put" => Some("PUT"),
        "patch" => Some("PATCH"),
        "delete" => Some("DELETE"),
        "head" => Some("HEAD"),
        "options" => Some("OPTIONS"),
        _ => None,
    }
}

fn decorated_http_methods(function: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    let text = function
        .parent()
        .filter(|parent| parent.kind().as_ref() == "decorated_definition")
        .map_or_else(
            || function.text().into_owned(),
            |parent| parent.text().into_owned(),
        );
    let mut methods = extract_named_calls(&text, &["api_view"])
        .into_iter()
        .flat_map(python_string_literals)
        .map(|method| method.to_ascii_uppercase())
        .filter(|method| {
            matches!(
                method.as_str(),
                "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
            )
        })
        .collect::<Vec<_>>();
    methods.sort();
    methods.dedup();
    if methods.is_empty() {
        methods.push("*".to_string());
    }
    methods
}

fn python_string_literals(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut values = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if !matches!(bytes[index], b'\'' | b'"') {
            index += 1;
            continue;
        }
        let quote = bytes[index];
        let start = index + 1;
        index = start;
        let mut escaped = false;
        while index < bytes.len() {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == quote {
                values.push(text[start..index].to_string());
                index += 1;
                break;
            }
            index += 1;
        }
    }
    values
}

#[allow(clippy::too_many_arguments)]
fn push_handler_entrypoint<'tree>(
    path: &str,
    name: &Node<'tree, StrDoc<SupportLang>>,
    handler: &str,
    routes: Vec<HttpRouteContext>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let location = location(path, name);
    evidence.push(Evidence {
        id: evidence_id(path, HANDLER_RULE_ID, name.range().start, name.range().end),
        kind: EvidenceKind::Entrypoint,
        capability: Capability::HttpRequestHandling,
        location: location.clone(),
        enclosing_symbol: Some(name.text().into_owned()),
        captures: BTreeMap::from([(
            "handler".to_string(),
            Capture {
                text: handler.to_string(),
                location,
            },
        )]),
        cwe_candidates: vec!["CWE-306".to_string(), "CWE-862".to_string()],
        tags: vec!["http".to_string(), "django".to_string(), "drf".to_string()],
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(name.range()),
            reachability: Some(reachability::classify(name, literals)),
            availability: Some(conditional.availability_for(name.range())),
            http_routes: routes,
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: HANDLER_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    });
}

#[allow(clippy::too_many_arguments)]
fn push_route_parameter_sources<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    routes: &[HttpRouteContext],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(parameters) = function.field("parameters") else {
        return;
    };
    for parameter in parameters.children().filter_map(parameter_name_node) {
        let name = parameter.text().into_owned();
        if matches!(name.as_str(), "self" | "request" | "user" | "format")
            || !routes
                .iter()
                .any(|route| route_mentions_parameter(&route.path, &name))
        {
            continue;
        }
        let source_node = function
            .dfs()
            .filter(|node| {
                node.kind().as_ref() == "identifier"
                    && node.range().start > parameters.range().end
                    && node.text().trim() == name
            })
            .min_by_key(|node| node.range().start)
            .unwrap_or_else(|| parameter.clone());
        let location = location(path, &source_node);
        evidence.push(Evidence {
            id: evidence_id(
                path,
                ROUTE_PARAMETER_RULE_ID,
                parameter.range().start,
                parameter.range().end,
            ),
            kind: EvidenceKind::Source,
            capability: Capability::HttpRequestData,
            location: location.clone(),
            enclosing_symbol: enclosing_symbol(function),
            captures: BTreeMap::from([(
                "name".to_string(),
                Capture {
                    text: name.clone(),
                    location,
                },
            )]),
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "http".to_string(),
                "request".to_string(),
                "django".to_string(),
                "route-parameter".to_string(),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: comments.is_in_comment(source_node.range()),
                reachability: Some(reachability::classify(&source_node, literals)),
                availability: Some(conditional.availability_for(source_node.range())),
                http_routes: routes
                    .iter()
                    .filter(|route| route_mentions_parameter(&route.path, &name))
                    .cloned()
                    .collect(),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: ROUTE_PARAMETER_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn parameter_name_node<'tree>(
    parameter: Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if parameter.kind().as_ref() == "identifier" {
        return Some(parameter);
    }
    parameter.field("name").or_else(|| {
        parameter
            .children()
            .find(|child| child.kind().as_ref() == "identifier")
    })
}

fn route_mentions_parameter(route: &str, name: &str) -> bool {
    route.contains(&format!("<{name}>"))
        || route.contains(&format!("P<{name}>"))
        || route.contains(&format!(":{name}>"))
}

fn enclosing_class_node<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.kind().as_ref() == "class_definition" {
            return Some(parent);
        }
        current = parent.parent();
    }
    None
}

fn merge_routes(existing: &mut Vec<HttpRouteContext>, routes: &[HttpRouteContext]) {
    for route in routes {
        if !existing.contains(route) {
            existing.push(route.clone());
        }
    }
    existing.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.method.cmp(&right.method))
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    format!("{path}:{start}:{end}:{rule_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_nested_django_routes_and_aliases() {
        let context = PythonProjectContext::from_sources(
            [
                (
                    "site/urls.py",
                    Language::Python,
                    "from django.urls import path, include\nurlpatterns = [path('api/', include('shop.urls'))]\n",
                ),
                (
                    "shop/urls.py",
                    Language::Python,
                    "from django.urls import re_path\nimport shop.views as views\nurlpatterns = [re_path(r'orders/(?P<order_id>\\d+)$', views.OrderView.as_view())]\n",
                ),
                (
                    "shop/views.py",
                    Language::Python,
                    "class OrderView:\n    def get(self, request, order_id):\n        pass\n",
                ),
            ]
            .into_iter(),
        );
        assert_eq!(
            context.routes_by_handler["shop.views:OrderView"][0].path,
            "/api/orders/(?P<order_id>\\d+)"
        );
    }
}
