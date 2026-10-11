//! Lazy connection context and actual URL/URLConnection resource consumers.
use super::*;

type N<'a> = Node<'a, StrDoc<SupportLang>>;
const URL: &str = "java.net.URL";
const URI: &str = "java.net.URI";
const CONNECTION: &str = "java.net.URLConnection";
const HTTP: &str = "java.net.HttpURLConnection";
const HTTPS: &str = "javax.net.ssl.HttpsURLConnection";

#[allow(clippy::too_many_arguments)]
pub(super) fn add<'a>(
    path: &str,
    root: &N<'a>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'a, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let resolver = Resolver {
        imports,
        declarations,
        bindings: root
            .dfs()
            .filter(|n| {
                matches!(
                    n.kind().as_ref(),
                    "variable_declarator" | "formal_parameter"
                )
            })
            .collect(),
    };
    let calls = invocations(root).collect::<Vec<_>>();
    let mut producers = BTreeMap::new();
    for call in &calls {
        if name(call).as_deref() != Some("openConnection") || arguments(call).len() > 1 {
            continue;
        }
        let Some(receiver) = call.field("object").filter(|n| resolver.owned(n, URL, 8)) else {
            continue;
        };
        let endpoint = resolver.endpoint(&receiver, 8).unwrap_or(receiver);
        let before = evidence.len();
        push(
            path,
            call,
            &endpoint,
            "java-url-connection",
            EvidenceKind::Resource,
            Capability::OutboundNetworkRequest,
            "endpoint",
            &["CWE-918"],
            &[
                "jdk",
                "url-connection",
                "outbound-request:construction-context",
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
        if evidence.len() > before {
            if let Some(proxy) = arguments(call).first() {
                evidence[before].captures.insert(
                    "proxy".into(),
                    Capture {
                        text: proxy.text().into_owned(),
                        location: location(path, proxy),
                    },
                );
                let direct = proxy.field("object").is_some_and(|object| {
                    resolver.canonical(&object, &object.text(), "java.net.Proxy")
                        && resolver.binding(&object).is_none()
                }) && proxy
                    .field("field")
                    .is_some_and(|field| field.text() == "NO_PROXY");
                if !direct {
                    evidence[before]
                        .tags
                        .push("outbound-request:unresolved-proxy-policy".into());
                }
            }
            producers.insert(
                (call.range().start, call.range().end),
                evidence[before].clone(),
            );
        }
    }
    for call in &calls {
        let Some(operation) = name(call) else {
            continue;
        };
        let Some(receiver) = call.field("object") else {
            continue;
        };
        let arity = arguments(call).len();
        let direct_url = matches!(operation.as_str(), "openStream" | "getContent")
            && (arity == 0 || operation == "getContent" && arity == 1)
            && resolver.owned(&receiver, URL, 8);
        let consumer = consumer_arity(&operation).is_some_and(|range| range.contains(&arity))
            && resolver.owned(&receiver, CONNECTION, 8)
            && (!matches!(operation.as_str(), "getResponseCode" | "getResponseMessage")
                || resolver.owned(&receiver, HTTP, 8)
                || resolver.owned(&receiver, HTTPS, 8));
        if !direct_url && !consumer {
            continue;
        }
        let producer = (!direct_url)
            .then(|| resolver.origin(&receiver, &producers, 8))
            .flatten();
        let mut values = BTreeMap::new();
        let endpoint = if direct_url {
            resolver.endpoint(&receiver, 8).map(|n| {
                values.insert("endpoint".into(), literals.evaluate(&n));
                Capture {
                    text: n.text().into_owned(),
                    location: location(path, &n),
                }
            })
        } else {
            if let Some(value) = producer
                .as_ref()
                .and_then(|e| e.context.literals.get("endpoint"))
            {
                values.insert("endpoint".into(), value.clone());
            }
            producer
                .as_ref()
                .and_then(|e| e.captures.get("endpoint").cloned())
        };
        let mut captures = BTreeMap::from([(
            "connection".into(),
            Capture {
                text: receiver.text().into_owned(),
                location: location(path, &receiver),
            },
        )]);
        if let Some(proxy) = producer.as_ref().and_then(|e| e.captures.get("proxy")) {
            captures.insert("proxy".into(), proxy.clone());
        }
        if let Some(endpoint) = endpoint {
            captures.insert("endpoint".into(), endpoint);
        }
        let unresolved = !captures.contains_key("endpoint");
        let before = evidence.len();
        push_evidence(
            path,
            call,
            if direct_url {
                "java-url-read"
            } else {
                "java-url-connection-consumer"
            },
            EvidenceKind::Sink,
            Capability::OutboundNetworkRequest,
            captures,
            values,
            &["CWE-918"],
            &["jdk", "url-connection", "outbound-request:dispatch"],
            comments,
            conditional,
            literals,
            evidence,
        );
        if evidence.len() > before {
            let sink = &mut evidence[before];
            if let Some(producer) = producer {
                if producer
                    .tags
                    .iter()
                    .any(|t| t == "outbound-request:unresolved-proxy-policy")
                {
                    sink.tags
                        .push("outbound-request:unresolved-proxy-policy".into());
                }
                sink.related_evidence.push(producer.id);
            }
            if unresolved {
                sink.tags
                    .push("outbound-request:unresolved-producer".into());
            }
        }
    }
}

fn name(node: &N<'_>) -> Option<String> {
    node.field("name").map(|n| n.text().into_owned())
}

fn consumer_arity(method: &str) -> Option<std::ops::RangeInclusive<usize>> {
    Some(match method {
        "connect"
        | "getInputStream"
        | "getOutputStream"
        | "getHeaderFields"
        | "getResponseCode"
        | "getResponseMessage"
        | "getContentType"
        | "getContentEncoding"
        | "getContentLength"
        | "getContentLengthLong"
        | "getDate"
        | "getExpiration"
        | "getLastModified" => 0..=0,
        "getContent" => 0..=1,
        "getHeaderField" | "getHeaderFieldKey" => 1..=1,
        "getHeaderFieldDate" | "getHeaderFieldInt" | "getHeaderFieldLong" => 2..=2,
        _ => return None,
    })
}

struct Resolver<'r, 'a> {
    imports: &'r BTreeSet<String>,
    declarations: &'r BTreeSet<String>,
    bindings: Vec<N<'a>>,
}

impl<'a> Resolver<'_, 'a> {
    fn canonical(&self, site: &N<'a>, ty: &str, expected: &str) -> bool {
        let short = short_type(expected);
        let generic_shadow = site.ancestors().any(|owner| {
            owner.children().any(|n| {
                n.kind().as_ref() == "type_parameters"
                    && n.dfs()
                        .any(|n| n.kind().as_ref() == "type_identifier" && n.text() == short)
            })
        });
        ty == expected
            || ty == short
                && !generic_shadow
                && imported_exact(self.imports, self.declarations, expected, short)
    }

    fn binding(&self, site: &N<'a>) -> Option<N<'a>> {
        let text = site.text();
        let explicit_this = text.starts_with("this.");
        let symbol = text.strip_prefix("this.").unwrap_or(&text);
        if !symbol
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '$'))
        {
            return None;
        }
        let owner = enclosing_type_start(site);
        let local = self
            .bindings
            .iter()
            .filter(|n| {
                !explicit_this
                    && n.range().end <= site.range().start
                    && n.field("name").is_some_and(|n| n.text() == symbol)
                    && n.parent()
                        .is_none_or(|p| p.kind().as_ref() != "field_declaration")
                    && (super::super::context::lexical_declaration_visible_at(n, site)
                        || n.kind().as_ref() == "formal_parameter"
                            && n.ancestors()
                                .find(|owner| {
                                    matches!(
                                        owner.kind().as_ref(),
                                        "method_declaration"
                                            | "constructor_declaration"
                                            | "lambda_expression"
                                    )
                                })
                                .is_some_and(|owner| {
                                    owner.range().start <= site.range().start
                                        && site.range().end <= owner.range().end
                                }))
            })
            .max_by_key(|n| n.range().start)
            .cloned();
        local.or_else(|| {
            self.bindings
                .iter()
                .find(|n| {
                    n.parent()
                        .is_some_and(|p| p.kind().as_ref() == "field_declaration")
                        && enclosing_type_start(n) == owner
                        && n.field("name").is_some_and(|n| n.text() == symbol)
                })
                .cloned()
        })
    }

    fn owned(&self, value: &N<'a>, expected: &str, depth: usize) -> bool {
        if depth == 0 {
            return false;
        }
        if value.kind().as_ref() == "parenthesized_expression" {
            return value
                .children()
                .find(|n| n.is_named())
                .is_some_and(|n| self.owned(&n, expected, depth - 1));
        }
        if matches!(
            value.kind().as_ref(),
            "cast_expression" | "object_creation_expression"
        ) {
            return value
                .field("type")
                .is_some_and(|ty| self.type_matches(value, &ty.text(), expected));
        }
        if value.kind().as_ref() == "method_invocation" {
            let Some(receiver) = value.field("object") else {
                return false;
            };
            let arity = arguments(value).len();
            return (expected == URL
                && name(value).as_deref() == Some("toURL")
                && arity == 0
                && self.owned(&receiver, URI, depth - 1))
                || expected == CONNECTION
                    && name(value).as_deref() == Some("openConnection")
                    && arity <= 1
                    && self.owned(&receiver, URL, depth - 1)
                || expected == URI
                    && name(value).as_deref() == Some("create")
                    && arity == 1
                    && self.canonical(&receiver, &receiver.text(), URI)
                    && self.binding(&receiver).is_none();
        }
        let Some(binding) = self.binding(value) else {
            return false;
        };
        let declaration = binding
            .field("type")
            .map(|_| binding.clone())
            .or_else(|| binding.parent());
        let Some(ty) = declaration.and_then(|n| n.field("type")) else {
            return false;
        };
        self.type_matches(value, &ty.text(), expected)
            || ty.text() == "var"
                && binding
                    .field("value")
                    .is_some_and(|n| self.owned(&n, expected, depth - 1))
    }

    fn type_matches(&self, site: &N<'a>, ty: &str, expected: &str) -> bool {
        self.canonical(site, ty, expected)
            || expected == CONNECTION
                && [HTTP, HTTPS]
                    .iter()
                    .any(|ty_name| self.canonical(site, ty, ty_name))
            || expected == HTTP && self.canonical(site, ty, HTTPS)
    }

    fn local_value(&self, site: &N<'a>) -> Option<N<'a>> {
        let binding = self.binding(site)?;
        if binding.parent()?.kind().as_ref() != "local_variable_declaration" {
            return None;
        }
        self.unchanged(&binding, site)
            .then(|| binding.field("value"))
            .flatten()
    }

    fn unchanged(&self, binding: &N<'a>, site: &N<'a>) -> bool {
        let Some(symbol) = binding.field("name") else {
            return false;
        };
        let Some(scope) = site.ancestors().find(|n| {
            matches!(
                n.kind().as_ref(),
                "method_declaration" | "constructor_declaration" | "lambda_expression"
            )
        }) else {
            return false;
        };
        if !binding.ancestors().any(|n| n.range() == scope.range()) {
            return false;
        }
        scope
            .dfs()
            .filter(|n| {
                n.kind().as_ref() == "identifier"
                    && n.text() == symbol.text()
                    && n.range().start >= binding.range().end
                    && n.range().end <= site.range().start
                    && super::super::context::lexical_declaration_visible_at(binding, n)
            })
            .all(|n| {
                // SDK reads/setup do not replace URL authority. A reassignment or
                // helper handoff does: keep the typed consumer, without fixed facts.
                n.parent().is_some_and(|p| {
                    p.kind().as_ref() == "method_invocation"
                        && p.field("object").is_some_and(|r| r.range() == n.range())
                        && name(&p).is_some_and(|m| {
                            consumer_arity(&m).is_some()
                                || matches!(
                                    m.as_str(),
                                    "toURL"
                                        | "openConnection"
                                        | "openStream"
                                        | "getURL"
                                        | "toString"
                                        | "setRequestMethod"
                                        | "setRequestProperty"
                                        | "addRequestProperty"
                                        | "setDoInput"
                                        | "setDoOutput"
                                        | "setUseCaches"
                                        | "setAllowUserInteraction"
                                        | "setConnectTimeout"
                                        | "setReadTimeout"
                                        | "setIfModifiedSince"
                                        | "setInstanceFollowRedirects"
                                        | "setHostnameVerifier"
                                        | "setSSLSocketFactory"
                                )
                        })
                })
            })
    }

    fn endpoint(&self, value: &N<'a>, depth: usize) -> Option<N<'a>> {
        if depth == 0 {
            return None;
        }
        if let Some(local) = self.local_value(value) {
            return self.endpoint(&local, depth - 1);
        }
        if value.kind().as_ref() == "parenthesized_expression" {
            return self.endpoint(&value.children().find(|n| n.is_named())?, depth - 1);
        }
        if value.kind().as_ref() == "object_creation_expression"
            && value.field("body").is_none()
            && [URL, URI].iter().any(|ty| self.owned(value, ty, depth))
        {
            let args = arguments(value);
            return (args.len() == 1).then(|| args[0].clone());
        }
        if value.kind().as_ref() == "method_invocation" {
            let receiver = value.field("object")?;
            if name(value).as_deref() == Some("toURL") && self.owned(&receiver, URI, depth) {
                return self.endpoint(&receiver, depth - 1);
            }
            if name(value).as_deref() == Some("create") && self.owned(value, URI, depth) {
                return arguments(value).into_iter().next();
            }
        }
        None
    }

    fn origin(
        &self,
        value: &N<'a>,
        producers: &BTreeMap<(usize, usize), Evidence>,
        depth: usize,
    ) -> Option<Evidence> {
        if depth == 0 {
            return None;
        }
        if let Some(e) = producers.get(&(value.range().start, value.range().end)) {
            return Some(e.clone());
        }
        if matches!(
            value.kind().as_ref(),
            "parenthesized_expression" | "cast_expression"
        ) {
            let child = value
                .field("value")
                .or_else(|| value.children().find(|n| n.is_named()))?;
            return self.origin(&child, producers, depth - 1);
        }
        let local = self.local_value(value)?;
        // Shared connection aliases keep ownership, without copying a fixed
        // policy/destination fact across another slot's possible configuration.
        if local.kind().as_ref() == "identifier" {
            return None;
        }
        self.origin(&local, producers, depth - 1)
    }
}
