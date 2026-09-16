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
use super::context::{enclosing_symbol, enclosing_type_start, lexical_declaration_visible_at};
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan java-serialization-xml-policy 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_java_serialization_observations<'tree>(
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
    // Replace the legacy name-only Java seeds with exact imported/typed policy.
    // This also prevents local ObjectMapper/ObjectInputStream lookalikes from
    // entering flow construction.
    evidence.retain(|item| {
        !matches!(
            item.rule_id.as_str(),
            "java-object-deserialization" | "java-deserialization-restriction"
        )
    });
    let imports = imports(root);
    let declarations = declared_types(root);
    let receivers = receiver_types(root);
    let initializers = variable_initializers(root);

    add_deserialization_observations(
        path,
        root,
        &imports,
        &declarations,
        &receivers,
        &initializers,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_xml_observations(
        path,
        root,
        &imports,
        &declarations,
        &receivers,
        &initializers,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_deserialization_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    receivers: &BTreeMap<(usize, String), String>,
    initializers: &BTreeMap<String, Node<'tree, StrDoc<SupportLang>>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let jackson = type_available(
        imports,
        declarations,
        "com.fasterxml.jackson.databind.ObjectMapper",
    );
    let yaml = type_available(imports, declarations, "org.yaml.snakeyaml.Yaml");
    let safe_yaml_constructor = type_available(
        imports,
        declarations,
        "org.yaml.snakeyaml.constructor.SafeConstructor",
    );
    let xstream = type_available(imports, declarations, "com.thoughtworks.xstream.XStream");
    let xstream_any_permission = type_available(
        imports,
        declarations,
        "com.thoughtworks.xstream.security.AnyTypePermission",
    );
    let xstream_no_permission = type_available(
        imports,
        declarations,
        "com.thoughtworks.xstream.security.NoTypePermission",
    );
    let native = type_available(imports, declarations, "java.io.ObjectInputStream");
    let xml_decoder = type_available(imports, declarations, "java.beans.XMLDecoder");

    for invocation in invocations(root) {
        let Some((object, operation)) = invocation_parts(&invocation) else {
            continue;
        };
        let args = arguments(&invocation);

        if jackson && receiver_is_at(&invocation, &object, "ObjectMapper", receivers) {
            if matches!(operation.as_str(), "readValue" | "treeToValue") && !args.is_empty() {
                remove_declarative_java_deserialization(path, &invocation, evidence);
                push(
                    path,
                    &invocation,
                    &args[0],
                    "java-jackson-object-deserialization",
                    EvidenceKind::Sink,
                    Capability::Deserialization,
                    "payload",
                    &["CWE-502"],
                    &["deserialization", "jackson", "typed-receiver"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
                if let Some(target) = args
                    .get(1)
                    .filter(|target| fixed_target(target.text().as_ref()))
                {
                    push(
                        path,
                        &invocation,
                        target,
                        "java-jackson-fixed-target-control",
                        EvidenceKind::Validation,
                        Capability::DeserializationRestriction,
                        "type",
                        &["CWE-502"],
                        &["deserialization", "jackson", "fixed-target"],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
            if matches!(
                operation.as_str(),
                "activateDefaultTyping" | "enableDefaultTyping"
            ) {
                push_without_capture(
                    path,
                    &invocation,
                    "java-jackson-default-typing-enabled",
                    EvidenceKind::SecurityConfiguration,
                    Capability::Deserialization,
                    &["CWE-502"],
                    &["deserialization", "jackson", "polymorphic-default-typing"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if yaml
            && receiver_is_at(&invocation, &object, "Yaml", receivers)
            && matches!(operation.as_str(), "load" | "loadAs")
        {
            if let Some(payload) = args.first() {
                push(
                    path,
                    &invocation,
                    payload,
                    "java-snakeyaml-load",
                    EvidenceKind::Sink,
                    Capability::Deserialization,
                    "payload",
                    &["CWE-502"],
                    &["deserialization", "snakeyaml"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            let receiver = object.text();
            if safe_yaml_constructor
                && initializer_text(receiver.trim(), initializers)
                    .is_some_and(|text| text.contains("SafeConstructor"))
            {
                push_without_capture(
                    path,
                    &invocation,
                    "java-snakeyaml-safe-constructor-control",
                    EvidenceKind::Validation,
                    Capability::DeserializationRestriction,
                    &["CWE-502"],
                    &["deserialization", "snakeyaml", "safe-constructor"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if operation == "load" {
                push_without_capture(
                    path,
                    &invocation,
                    "java-snakeyaml-constructor-policy-not-observed",
                    EvidenceKind::SecurityConfiguration,
                    Capability::Deserialization,
                    &["CWE-502"],
                    &["deserialization", "snakeyaml", "constructor-policy-review"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
            if operation == "loadAs"
                && args
                    .get(1)
                    .is_some_and(|target| fixed_target(target.text().as_ref()))
            {
                push(
                    path,
                    &invocation,
                    &args[1],
                    "java-snakeyaml-fixed-target-control",
                    EvidenceKind::Validation,
                    Capability::DeserializationRestriction,
                    "type",
                    &["CWE-502"],
                    &["deserialization", "snakeyaml", "fixed-target"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if xstream && receiver_is_at(&invocation, &object, "XStream", receivers) {
            if operation == "fromXML"
                && let Some(payload) = args.first()
            {
                push(
                    path,
                    &invocation,
                    payload,
                    "java-xstream-object-deserialization",
                    EvidenceKind::Sink,
                    Capability::Deserialization,
                    "payload",
                    &["CWE-502"],
                    &["deserialization", "xstream", "object-graph"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if matches!(operation.as_str(), "allowTypes" | "allowTypesByWildcard")
                && broad_type_permission(invocation.text().as_ref())
            {
                push_without_capture(
                    path,
                    &invocation,
                    "java-xstream-broad-type-permission",
                    EvidenceKind::SecurityConfiguration,
                    Capability::Deserialization,
                    &["CWE-502"],
                    &["deserialization", "xstream", "broad-type-permission"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if matches!(operation.as_str(), "allowTypes" | "allowTypesByWildcard") {
                push_without_capture(
                    path,
                    &invocation,
                    "java-xstream-type-allowlist-control",
                    EvidenceKind::Validation,
                    Capability::DeserializationRestriction,
                    &["CWE-502"],
                    &["deserialization", "xstream", "type-allowlist"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if operation == "addPermission"
                && xstream_any_permission
                && invocation.text().contains("AnyTypePermission.ANY")
            {
                push_without_capture(
                    path,
                    &invocation,
                    "java-xstream-any-type-permission",
                    EvidenceKind::SecurityConfiguration,
                    Capability::Deserialization,
                    &["CWE-502"],
                    &["deserialization", "xstream", "any-type-permission"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else if operation == "addPermission"
                && xstream_no_permission
                && invocation.text().contains("NoTypePermission.NONE")
            {
                push_without_capture(
                    path,
                    &invocation,
                    "java-xstream-deny-all-control",
                    EvidenceKind::Validation,
                    Capability::DeserializationRestriction,
                    &["CWE-502"],
                    &["deserialization", "xstream", "deny-all-baseline"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if native && receiver_is_at(&invocation, &object, "ObjectInputStream", receivers) {
            if operation == "readObject" {
                remove_declarative_java_deserialization(path, &invocation, evidence);
                if let Some(payload) = receiver_constructor_argument(&object, initializers) {
                    push(
                        path,
                        &invocation,
                        &payload,
                        "java-native-object-deserialization",
                        EvidenceKind::Sink,
                        Capability::Deserialization,
                        "payload",
                        &["CWE-502"],
                        &["deserialization", "java-native", "object-graph"],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                } else {
                    push(
                        path,
                        &invocation,
                        &object,
                        "java-native-object-deserialization",
                        EvidenceKind::Sink,
                        Capability::Deserialization,
                        "stream",
                        &["CWE-502"],
                        &["deserialization", "java-native", "object-graph"],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            } else if operation == "setObjectInputFilter" {
                push_without_capture(
                    path,
                    &invocation,
                    "java-object-input-filter-control",
                    EvidenceKind::Validation,
                    Capability::DeserializationRestriction,
                    &["CWE-502"],
                    &["deserialization", "java-native", "object-input-filter"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        if xml_decoder
            && receiver_is_at(&invocation, &object, "XMLDecoder", receivers)
            && operation == "readObject"
        {
            let captured = receiver_constructor_argument(&object, initializers).unwrap_or(object);
            push(
                path,
                &invocation,
                &captured,
                "java-xml-decoder-deserialization",
                EvidenceKind::Sink,
                Capability::Deserialization,
                "payload",
                &["CWE-502"],
                &["deserialization", "xml-decoder", "object-graph"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    add_polymorphic_type_controls(
        path,
        root,
        imports,
        declarations,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_xml_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    receivers: &BTreeMap<(usize, String), String>,
    initializers: &BTreeMap<String, Node<'tree, StrDoc<SupportLang>>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let document_builder =
        type_available(imports, declarations, "javax.xml.parsers.DocumentBuilder");
    let document_factory = type_available(
        imports,
        declarations,
        "javax.xml.parsers.DocumentBuilderFactory",
    );
    let sax_parser = type_available(imports, declarations, "javax.xml.parsers.SAXParser");
    let sax_factory = type_available(imports, declarations, "javax.xml.parsers.SAXParserFactory");
    let stream_factory = type_available(imports, declarations, "javax.xml.stream.XMLInputFactory");
    let transformer = type_available(imports, declarations, "javax.xml.transform.Transformer");
    let transformer_factory = type_available(
        imports,
        declarations,
        "javax.xml.transform.TransformerFactory",
    );
    let schema_factory =
        type_available(imports, declarations, "javax.xml.validation.SchemaFactory");

    for invocation in invocations(root) {
        let Some((object, operation)) = invocation_parts(&invocation) else {
            continue;
        };
        let args = arguments(&invocation);
        let object_name = object.text();
        let object_name = object_name.trim();

        let builder_sink = document_builder
            && receiver_is_at(&invocation, &object, "DocumentBuilder", receivers)
            && operation == "parse";
        let sax_sink = sax_parser
            && receiver_is_at(&invocation, &object, "SAXParser", receivers)
            && operation == "parse";
        let stream_sink = stream_factory
            && receiver_is_at(&invocation, &object, "XMLInputFactory", receivers)
            && operation == "createXMLStreamReader";
        let transformer_sink = transformer
            && receiver_is_at(&invocation, &object, "Transformer", receivers)
            && operation == "transform";
        let schema_sink = schema_factory
            && receiver_is_at(&invocation, &object, "SchemaFactory", receivers)
            && operation == "newSchema";
        if (builder_sink || sax_sink || stream_sink || transformer_sink || schema_sink)
            && let Some(payload) = args.first()
        {
            let family = if builder_sink {
                "document-builder"
            } else if sax_sink {
                "sax-parser"
            } else if stream_sink {
                "stax"
            } else if transformer_sink {
                "transformer"
            } else {
                "schema-factory"
            };
            push(
                path,
                &invocation,
                payload,
                "java-xml-parser-input",
                EvidenceKind::Sink,
                Capability::XmlParsing,
                "payload",
                &["CWE-611"],
                &["xml", "external-entity", family],
                comments,
                conditional,
                literals,
                evidence,
            );

            let policy_receiver = derived_factory(object_name, initializers);
            let policy_receiver = policy_receiver.as_deref().unwrap_or(object_name);
            if !xml_hardening_before(&invocation, policy_receiver, family) {
                push_without_capture(
                    path,
                    &invocation,
                    "java-xml-external-access-policy-not-observed",
                    EvidenceKind::SecurityConfiguration,
                    Capability::XmlParsing,
                    &["CWE-611"],
                    &["xml", "external-entity", family, "hardening-not-observed"],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }

        let factory_receiver = (document_factory
            && receiver_is_at(&invocation, &object, "DocumentBuilderFactory", receivers))
            || (sax_factory && receiver_is_at(&invocation, &object, "SAXParserFactory", receivers))
            || (stream_factory
                && receiver_is_at(&invocation, &object, "XMLInputFactory", receivers))
            || (transformer_factory
                && receiver_is_at(&invocation, &object, "TransformerFactory", receivers))
            || (schema_factory && receiver_is_at(&invocation, &object, "SchemaFactory", receivers));
        if factory_receiver && is_xml_hardening_call(&invocation, &operation) {
            push_without_capture(
                path,
                &invocation,
                "java-xml-external-access-restriction-control",
                EvidenceKind::Validation,
                Capability::XmlParsing,
                &["CWE-611"],
                &["xml", "external-entity", "explicit-hardening"],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn fixed_target(text: &str) -> bool {
    let compact = compact(text);
    let Some(target) = compact.strip_suffix(".class") else {
        return false;
    };
    !matches!(
        target,
        "Object" | "java.lang.Object" | "Map" | "java.util.Map" | "HashMap" | "java.util.HashMap"
    )
}

#[allow(clippy::too_many_arguments)]
fn add_polymorphic_type_controls<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if type_available(
        imports,
        declarations,
        "com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator",
    ) {
        for invocation in invocations(root).filter(|invocation| {
            invocation
                .field("name")
                .is_some_and(|name| name.text().as_ref() == "build")
                && invocation
                    .text()
                    .contains("BasicPolymorphicTypeValidator.builder()")
                && invocation.text().contains("allowIfSubType(")
        }) {
            let broad = broad_type_permission(invocation.text().as_ref());
            push_without_capture(
                path,
                &invocation,
                if broad {
                    "java-jackson-broad-polymorphic-type-permission"
                } else {
                    "java-jackson-polymorphic-type-allowlist-control"
                },
                if broad {
                    EvidenceKind::SecurityConfiguration
                } else {
                    EvidenceKind::Validation
                },
                if broad {
                    Capability::Deserialization
                } else {
                    Capability::DeserializationRestriction
                },
                &["CWE-502"],
                &[
                    "deserialization",
                    "jackson",
                    if broad {
                        "broad-polymorphic-type"
                    } else {
                        "polymorphic-type-allowlist"
                    },
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }

    if type_available(
        imports,
        declarations,
        "com.fasterxml.jackson.annotation.JsonTypeInfo",
    ) {
        for annotation in root
            .dfs()
            .filter(|node| matches!(node.kind().as_ref(), "annotation" | "marker_annotation"))
            .filter(|node| node.text().trim_start().starts_with("@JsonTypeInfo"))
        {
            let text = compact(annotation.text().as_ref());
            let class_id = text.contains("Id.CLASS") || text.contains("Id.MINIMAL_CLASS");
            let named_allowlist = text.contains("Id.NAME")
                && type_available(
                    imports,
                    declarations,
                    "com.fasterxml.jackson.annotation.JsonSubTypes",
                )
                && annotation
                    .parent()
                    .is_some_and(|parent| parent.text().contains("@JsonSubTypes"));
            if class_id || named_allowlist {
                push_without_capture(
                    path,
                    &annotation,
                    if class_id {
                        "java-jackson-class-name-polymorphism"
                    } else {
                        "java-jackson-named-subtype-control"
                    },
                    if class_id {
                        EvidenceKind::SecurityConfiguration
                    } else {
                        EvidenceKind::Validation
                    },
                    if class_id {
                        Capability::Deserialization
                    } else {
                        Capability::DeserializationRestriction
                    },
                    &["CWE-502"],
                    &[
                        "deserialization",
                        "jackson",
                        if class_id {
                            "class-name-polymorphism"
                        } else {
                            "named-subtype-allowlist"
                        },
                    ],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

fn broad_type_permission(text: &str) -> bool {
    let compact = compact(text);
    compact.contains("Object.class")
        || compact.contains("java.lang.Object.class")
        || compact.contains("\"**\"")
        || compact.contains("\"*\"")
}

fn xml_hardening_before(
    sink: &Node<'_, StrDoc<SupportLang>>,
    receiver: &str,
    family: &str,
) -> bool {
    let Some(method) = sink.ancestors().find(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "constructor_declaration"
        )
    }) else {
        return false;
    };
    method.dfs().any(|node| {
        node.kind().as_ref() == "method_invocation"
            && node.range().start < sink.range().start
            && invocation_parts(&node).is_some_and(|(object, operation)| {
                object.text().trim() == receiver
                    && is_family_hardening_call(&node, &operation, family)
            })
    })
}

fn is_xml_hardening_call(invocation: &Node<'_, StrDoc<SupportLang>>, operation: &str) -> bool {
    [
        "setFeature",
        "setProperty",
        "setAttribute",
        "setXIncludeAware",
        "setExpandEntityReferences",
    ]
    .contains(&operation)
        && hardening_value(invocation.text().as_ref())
}

fn is_family_hardening_call(
    invocation: &Node<'_, StrDoc<SupportLang>>,
    operation: &str,
    family: &str,
) -> bool {
    let text = compact(invocation.text().as_ref());
    match family {
        "document-builder" | "sax-parser" => {
            operation == "setFeature"
                && text.contains("disallow-doctype-decl")
                && text.ends_with(",true)")
                || operation == "setFeature"
                    && (text.contains("external-general-entities")
                        || text.contains("external-parameter-entities")
                        || text.contains("load-external-dtd"))
                    && text.ends_with(",false)")
                || operation == "setAttribute"
                    && text.contains("ACCESS_EXTERNAL_DTD")
                    && empty_string_value(&text)
        }
        "stax" => {
            operation == "setProperty"
                && (text.contains("SUPPORT_DTD")
                    || text.contains("IS_SUPPORTING_EXTERNAL_ENTITIES"))
                && text.ends_with(",false)")
        }
        "transformer" => {
            operation == "setAttribute"
                && text.contains("ACCESS_EXTERNAL_STYLESHEET")
                && empty_string_value(&text)
        }
        "schema-factory" => {
            operation == "setProperty"
                && (text.contains("ACCESS_EXTERNAL_DTD") || text.contains("ACCESS_EXTERNAL_SCHEMA"))
                && empty_string_value(&text)
        }
        _ => false,
    }
}

fn hardening_value(text: &str) -> bool {
    let text = compact(text);
    (text.ends_with(",false)")
        && (text.contains("external")
            || text.contains("SUPPORT_DTD")
            || text.contains("setXIncludeAware")
            || text.contains("setExpandEntityReferences")))
        || (text.ends_with(",true)") && text.contains("disallow-doctype-decl"))
        || empty_string_value(&text)
}

fn empty_string_value(text: &str) -> bool {
    text.ends_with(",\"\")")
}

fn derived_factory(
    receiver: &str,
    initializers: &BTreeMap<String, Node<'_, StrDoc<SupportLang>>>,
) -> Option<String> {
    let initializer = initializers.get(receiver)?;
    let (object, operation) = invocation_parts(initializer)?;
    matches!(
        operation.as_str(),
        "newDocumentBuilder" | "newSAXParser" | "newTransformer"
    )
    .then(|| object.text().trim().to_string())
}

fn constructor_argument<'tree>(
    receiver: &str,
    initializers: &BTreeMap<String, Node<'tree, StrDoc<SupportLang>>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let initializer = initializers.get(receiver)?;
    initializer
        .dfs()
        .find(|node| node.kind().as_ref() == "object_creation_expression")
        .and_then(|creation| creation.field("arguments"))
        .and_then(|arguments| arguments.children().find(|child| child.is_named()))
}

fn receiver_constructor_argument<'tree>(
    receiver: &Node<'tree, StrDoc<SupportLang>>,
    initializers: &BTreeMap<String, Node<'tree, StrDoc<SupportLang>>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if receiver.kind().as_ref() == "object_creation_expression" {
        return receiver
            .field("arguments")
            .and_then(|arguments| arguments.children().find(|child| child.is_named()));
    }
    constructor_argument(receiver.text().trim(), initializers)
}

fn initializer_text<'a>(
    receiver: &str,
    initializers: &'a BTreeMap<String, Node<'_, StrDoc<SupportLang>>>,
) -> Option<std::borrow::Cow<'a, str>> {
    initializers.get(receiver).map(Node::text)
}

fn remove_declarative_java_deserialization(
    path: &str,
    invocation: &Node<'_, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    evidence.retain(|item| {
        !(matches!(
            item.rule_id.as_str(),
            "java-object-deserialization" | "java-deserialization-restriction"
        ) && item.location.path == path
            && item.location.start.byte_offset == invocation.range().start)
    });
}

fn invocations<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
}

fn invocation_parts<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    Some((
        invocation.field("object")?,
        invocation.field("name")?.text().trim().to_string(),
    ))
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

fn receiver_is_at(
    use_site: &Node<'_, StrDoc<SupportLang>>,
    receiver: &Node<'_, StrDoc<SupportLang>>,
    expected: &str,
    receivers: &BTreeMap<(usize, String), String>,
) -> bool {
    let text = receiver.text();
    let text = text.trim();
    if receiver.kind().as_ref() == "object_creation_expression" {
        return receiver
            .field("type")
            .is_some_and(|kind| short_type(kind.text().as_ref()) == expected);
    }
    let method = use_site.ancestors().find(|node| {
        matches!(
            node.kind().as_ref(),
            "method_declaration" | "constructor_declaration"
        )
    });
    if let Some(method) = method {
        let mut scoped_type = None;
        for node in method.dfs().filter(|node| {
            node.range().start <= use_site.range().start
                && matches!(
                    node.kind().as_ref(),
                    "parameter" | "formal_parameter" | "local_variable_declaration"
                )
        }) {
            if matches!(node.kind().as_ref(), "parameter" | "formal_parameter")
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == text)
                && let Some(kind) = node.field("type")
            {
                scoped_type = Some(kind.text().into_owned());
            }
            if node.kind().as_ref() == "local_variable_declaration"
                && lexical_declaration_visible_at(&node, use_site)
                && let Some(kind) = node.field("type")
                && node.children().any(|child| {
                    child.kind().as_ref() == "variable_declarator"
                        && child
                            .field("name")
                            .is_some_and(|name| name.text().trim() == text)
                })
            {
                scoped_type = Some(kind.text().into_owned());
            }
        }
        if let Some(kind) = scoped_type {
            return short_type(&kind) == expected;
        }
    }
    // Field receivers have class scope and are safe to resolve from the file map.
    enclosing_type_start(use_site)
        .and_then(|owner| receivers.get(&(owner, text.to_string())))
        .is_some_and(|kind| short_type(kind) == expected)
}

fn receiver_types(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeMap<(usize, String), String> {
    let mut result = BTreeMap::new();
    for node in root.dfs() {
        if node.kind().as_ref() == "field_declaration"
            && let Some(kind) = node.field("type")
        {
            for variable in node
                .children()
                .filter(|child| child.kind().as_ref() == "variable_declarator")
            {
                if let Some(name) = variable.field("name")
                    && let Some(owner) = enclosing_type_start(&node)
                {
                    result.insert((owner, name.text().into_owned()), kind.text().into_owned());
                }
            }
        }
    }
    result
}

fn variable_initializers<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> BTreeMap<String, Node<'tree, StrDoc<SupportLang>>> {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator")
        .filter_map(|node| {
            Some((
                node.field("name")?.text().into_owned(),
                node.field("value")?,
            ))
        })
        .collect()
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

fn type_available(
    imports: &BTreeSet<String>,
    declarations: &BTreeSet<String>,
    canonical: &str,
) -> bool {
    let (namespace, short) = canonical.rsplit_once('.').unwrap_or(("", canonical));
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
    let literal_values = BTreeMap::from([(role.to_string(), literals.evaluate(captured))]);
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
        literal_values,
        cwes,
        tags,
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
        BTreeMap::new(),
        cwes,
        tags,
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
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    literal_values: BTreeMap<String, mehscan_core::LiteralEvaluation>,
    cwes: &[&str],
    tags: &[&str],
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
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
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
