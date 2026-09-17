use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use ast_grep_core::{Doc, Node};
use mehscan_core::{Language, LiteralEvaluation, LiteralState, LiteralValue};

const MAX_EVALUATION_DEPTH: usize = 16;

#[derive(Clone)]
struct ConstantBinding<'tree, D: Doc> {
    initializer: Node<'tree, D>,
    scope: Range<usize>,
    declaration_start: usize,
}

pub(crate) struct LiteralEnvironment<'tree, D: Doc> {
    constants: BTreeMap<String, Vec<ConstantBinding<'tree, D>>>,
    ambiguous_names: BTreeSet<String>,
    enum_members: BTreeSet<String>,
}

impl<'tree, D: Doc> LiteralEnvironment<'tree, D> {
    pub(crate) fn build(root: &Node<'tree, D>, language: Language) -> Self {
        let mut constants: BTreeMap<String, Vec<ConstantBinding<'tree, D>>> = BTreeMap::new();
        let mut ambiguous_names = BTreeSet::new();
        let mut enum_members = BTreeSet::new();
        for node in root.dfs() {
            collect_enum_members(&node, &mut enum_members);
            if is_mutable_declaration(&node, language)
                && let Some(name) = declaration_name(&node)
            {
                ambiguous_names.insert(name);
            }
            if is_parameter_identifier(&node) {
                ambiguous_names.insert(node.text().into_owned());
            }
            if !is_constant_declarator(&node, language) {
                continue;
            }
            let Some(name) = declaration_name(&node) else {
                continue;
            };
            let Some(initializer) = declaration_initializer(&node, language) else {
                continue;
            };
            let scope = declaration_scope(&node, root);
            constants.entry(name).or_default().push(ConstantBinding {
                initializer,
                scope,
                declaration_start: node.range().start,
            });
        }
        for bindings in constants.values_mut() {
            bindings.sort_by_key(|binding| binding.declaration_start);
        }
        if matches!(language, Language::Python | Language::Php) {
            ambiguous_names.extend(
                constants
                    .iter()
                    .filter(|(_, bindings)| {
                        if language != Language::Php {
                            return bindings.len() > 1;
                        }
                        // PHP locals with the same spelling in independent
                        // functions do not make one another's literals mutable.
                        let owner = |binding: &ConstantBinding<'_, D>| {
                            binding
                                .initializer
                                .ancestors()
                                .find(|n| {
                                    matches!(
                                        n.kind().as_ref(),
                                        "function_definition"
                                            | "method_declaration"
                                            | "anonymous_function"
                                            | "arrow_function"
                                    )
                                })
                                .map_or_else(|| root.range(), |n| n.range())
                        };
                        bindings.iter().enumerate().any(|(index, binding)| {
                            bindings[index + 1..]
                                .iter()
                                .any(|other| owner(binding) == owner(other))
                        })
                    })
                    .map(|(name, _)| name.clone()),
            );
        }
        Self {
            constants,
            ambiguous_names,
            enum_members,
        }
    }

    pub(crate) fn evaluate(&self, node: &Node<'tree, D>) -> LiteralEvaluation {
        self.evaluate_inner(node, 0, &mut BTreeSet::new())
    }

    pub(crate) fn known_bool(&self, node: &Node<'tree, D>) -> Option<bool> {
        match self.evaluate(node).value {
            Some(LiteralValue::Boolean(value)) => Some(value),
            _ => None,
        }
    }

    fn evaluate_inner(
        &self,
        node: &Node<'tree, D>,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> LiteralEvaluation {
        if depth >= MAX_EVALUATION_DEPTH {
            return unknown(Vec::new());
        }
        let text = node.text();
        let text = text.trim();
        let kind = node.kind();
        let kind = kind.as_ref();

        if let Some(value) = direct_boolean(text) {
            return known(LiteralValue::Boolean(value));
        }
        if is_null(text) {
            return known(LiteralValue::Null);
        }
        if kind == "encapsed_string"
            && node.dfs().any(|n| {
                matches!(
                    n.kind().as_ref(),
                    "variable_name" | "dynamic_variable_name" | "subscript_expression"
                )
            })
        {
            // PHP's $name/{$name} interpolation is not the shared brace grammar.
            // Retain fragments and dynamic references rather than folding it.
            return partial(
                node.children()
                    .filter(|n| n.kind().as_ref() == "string_content")
                    .map(|n| n.text().into_owned())
                    .collect(),
                node.dfs()
                    .filter(|n| n.kind().as_ref() == "variable_name")
                    .map(|n| n.text().into_owned())
                    .collect(),
            );
        }
        if is_interpolated_string(text, kind) {
            return self.evaluate_interpolation(text, node, depth, visiting);
        }
        if is_plain_string(text, kind) {
            return known(LiteralValue::String(decode_string(text)));
        }
        if is_number(text, kind) {
            return known(LiteralValue::Number(text.replace('_', "")));
        }
        if is_signed_number(kind, text) {
            let children = node
                .children()
                .filter(|child| child.is_named())
                .collect::<Vec<_>>();
            if children.len() == 1
                && let Some(LiteralValue::Number(number)) =
                    self.evaluate_inner(&children[0], depth + 1, visiting).value
            {
                return known(LiteralValue::Number(format!("{}{number}", &text[..1])));
            }
        }
        if is_parenthesized(kind) {
            let children = node
                .children()
                .filter(|child| child.is_named())
                .collect::<Vec<_>>();
            if children.len() == 1 {
                return self.evaluate_inner(&children[0], depth + 1, visiting);
            }
        }
        if is_transparent_wrapper(kind) {
            let children = node
                .children()
                .filter(|child| child.is_named())
                .collect::<Vec<_>>();
            if children.len() == 1 {
                return self.evaluate_inner(&children[0], depth + 1, visiting);
            }
        }
        if is_string_concatenation(node) {
            return self.evaluate_concatenation(node, depth, visiting);
        }
        if is_array_kind(kind) {
            return self.evaluate_array(node, depth, visiting);
        }
        if is_map_kind(kind) {
            return self.evaluate_map(node, depth, visiting);
        }

        let normalized_member = text.replace("::", ".");
        if self.enum_members.contains(&normalized_member) {
            return known(LiteralValue::Enum(normalized_member));
        }
        if is_identifier(text) {
            return self.evaluate_reference(text, node, depth, visiting);
        }
        if is_symbolic_reference(text) {
            return unknown(vec![text.replace("::", ".")]);
        }
        unknown(Vec::new())
    }

    fn evaluate_reference(
        &self,
        name: &str,
        use_node: &Node<'tree, D>,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> LiteralEvaluation {
        if self.ambiguous_names.contains(name) {
            return unknown(vec![name.to_string()]);
        }
        if !visiting.insert(name.to_string()) {
            return unknown(vec![name.to_string()]);
        }
        let binding = self.resolve_binding(name, use_node);
        let mut evaluation = binding.map_or_else(
            || unknown(vec![name.to_string()]),
            |binding| self.evaluate_inner(&binding.initializer, depth + 1, visiting),
        );
        visiting.remove(name);
        if matches!(
            evaluation.value,
            Some(LiteralValue::Array(_) | LiteralValue::Map(_))
        ) {
            return unknown(vec![name.to_string()]);
        }
        if binding.is_some() && !evaluation.references.iter().any(|item| item == name) {
            evaluation.references.insert(0, name.to_string());
        }
        evaluation
    }

    fn resolve_binding(
        &self,
        name: &str,
        use_node: &Node<'tree, D>,
    ) -> Option<&ConstantBinding<'tree, D>> {
        let use_range = use_node.range();
        self.constants
            .get(name)?
            .iter()
            .filter(|binding| {
                binding.declaration_start < use_range.start
                    && binding.scope.start <= use_range.start
                    && binding.scope.end >= use_range.end
            })
            .min_by_key(|binding| {
                (
                    binding.scope.end - binding.scope.start,
                    usize::MAX - binding.declaration_start,
                )
            })
    }

    fn evaluate_concatenation(
        &self,
        node: &Node<'tree, D>,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> LiteralEvaluation {
        let Some(left) = node.field("left") else {
            return unknown(Vec::new());
        };
        let Some(right) = node.field("right") else {
            return unknown(Vec::new());
        };
        if operator_between(node, &left, &right) != "+" {
            return unknown(Vec::new());
        }
        let left_value = self.evaluate_inner(&left, depth + 1, visiting);
        let right_value = self.evaluate_inner(&right, depth + 1, visiting);
        let mut references = left_value.references.clone();
        append_unique(&mut references, right_value.references.iter().cloned());
        if let (Some(LiteralValue::String(left)), Some(LiteralValue::String(right))) =
            (&left_value.value, &right_value.value)
        {
            return LiteralEvaluation {
                state: LiteralState::Known,
                value: Some(LiteralValue::String(format!("{left}{right}"))),
                constant_fragments: Vec::new(),
                references,
            };
        }
        let string_like = matches!(left_value.value, Some(LiteralValue::String(_)))
            || matches!(right_value.value, Some(LiteralValue::String(_)))
            || left_value.state == LiteralState::Partial
            || right_value.state == LiteralState::Partial;
        if !string_like {
            return unknown(references);
        }
        let mut fragments = fragments_for(&left_value);
        fragments.extend(fragments_for(&right_value));
        if fragments.is_empty() {
            unknown(references)
        } else {
            partial(fragments, references)
        }
    }

    fn evaluate_interpolation(
        &self,
        text: &str,
        use_node: &Node<'tree, D>,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> LiteralEvaluation {
        let (body, javascript) = interpolation_body(text);
        let mut rendered = String::new();
        let mut fragments = Vec::new();
        let mut references = Vec::new();
        let mut cursor = 0;
        let mut all_known = true;
        while let Some((open, expression_start)) = next_interpolation(body, cursor, javascript) {
            let literal = &body[cursor..open];
            rendered.push_str(literal);
            if !literal.is_empty() {
                fragments.push(unescape_braces(literal));
            }
            let Some(close) = body[expression_start..].find('}') else {
                return partial(fragments, references);
            };
            let close = expression_start + close;
            let expression = body[expression_start..close].trim();
            if !expression.is_empty() {
                references.push(expression.to_string());
            }
            let evaluation = if is_identifier(expression) {
                self.evaluate_reference(expression, use_node, depth + 1, visiting)
            } else if self.enum_members.contains(&expression.replace("::", ".")) {
                known(LiteralValue::Enum(expression.replace("::", ".")))
            } else {
                unknown(Vec::new())
            };
            if let Some(value) = evaluation.value.as_ref().and_then(scalar_text) {
                rendered.push_str(&value);
            } else {
                all_known = false;
            }
            cursor = close + 1;
        }
        let trailing = &body[cursor..];
        rendered.push_str(trailing);
        if !trailing.is_empty() {
            fragments.push(unescape_braces(trailing));
        }
        if all_known {
            LiteralEvaluation {
                state: LiteralState::Known,
                value: Some(LiteralValue::String(unescape_braces(&rendered))),
                constant_fragments: Vec::new(),
                references,
            }
        } else {
            partial(fragments, references)
        }
    }

    fn evaluate_array(
        &self,
        node: &Node<'tree, D>,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> LiteralEvaluation {
        let mut values = Vec::new();
        let mut references = Vec::new();
        for child in node.children().filter(|child| child.is_named()) {
            let evaluation = self.evaluate_inner(&child, depth + 1, visiting);
            append_unique(&mut references, evaluation.references.iter().cloned());
            let Some(value) = evaluation.value else {
                return unknown(references);
            };
            values.push(value);
        }
        LiteralEvaluation {
            state: LiteralState::Known,
            value: Some(LiteralValue::Array(values)),
            constant_fragments: Vec::new(),
            references,
        }
    }

    fn evaluate_map(
        &self,
        node: &Node<'tree, D>,
        depth: usize,
        visiting: &mut BTreeSet<String>,
    ) -> LiteralEvaluation {
        let mut values = BTreeMap::new();
        let mut references = Vec::new();
        for pair in node.children().filter(|child| child.is_named()) {
            if !is_pair_kind(pair.kind().as_ref()) {
                return unknown(references);
            }
            let Some(key) = pair.field("key") else {
                return unknown(references);
            };
            let Some(value) = pair.field("value") else {
                return unknown(references);
            };
            let key = if matches!(
                key.kind().as_ref(),
                "property_identifier" | "shorthand_property_identifier"
            ) {
                known(LiteralValue::String(key.text().into_owned()))
            } else {
                self.evaluate_inner(&key, depth + 1, visiting)
            };
            let value = self.evaluate_inner(&value, depth + 1, visiting);
            append_unique(&mut references, key.references.iter().cloned());
            append_unique(&mut references, value.references.iter().cloned());
            let Some(key) = key.value.as_ref().and_then(scalar_text) else {
                return unknown(references);
            };
            let Some(value) = value.value else {
                return unknown(references);
            };
            values.insert(key, value);
        }
        LiteralEvaluation {
            state: LiteralState::Known,
            value: Some(LiteralValue::Map(values)),
            constant_fragments: Vec::new(),
            references,
        }
    }
}

fn collect_enum_members<D: Doc>(node: &Node<'_, D>, output: &mut BTreeSet<String>) {
    if node.kind().as_ref() != "enum_declaration" {
        return;
    }
    let Some(name) = node.field("name") else {
        return;
    };
    let name = name.text();
    for member in node.dfs().filter(|candidate| {
        matches!(
            candidate.kind().as_ref(),
            "enum_member" | "enum_member_declaration" | "enum_constant"
        )
    }) {
        if let Some(member_name) = member.field("name").or_else(|| {
            member
                .children()
                .find(|child| child.kind().as_ref() == "identifier")
        }) {
            output.insert(format!("{name}.{}", member_name.text()));
        }
    }
}

fn is_constant_declarator<D: Doc>(node: &Node<'_, D>, language: Language) -> bool {
    let kind = node.kind();
    let kind = kind.as_ref();
    match language {
        // C-family constant folding needs declarator/type and preprocessor
        // semantics. Until that bounded pass exists, keep values unknown
        // instead of treating ordinary declarations as immutable constants.
        Language::C | Language::Cpp => false,
        Language::Kotlin => false,
        Language::Javascript | Language::Typescript | Language::Tsx => {
            kind == "variable_declarator"
                && ancestor_matches(node, 3, |ancestor| {
                    ancestor.kind().as_ref() == "lexical_declaration"
                        && ancestor.text().trim_start().starts_with("const ")
                })
        }
        Language::Csharp => {
            kind == "variable_declarator"
                && ancestor_matches(node, 4, |ancestor| {
                    ancestor.text().trim_start().starts_with("const ")
                        || ancestor.text().contains(" const ")
                })
        }
        Language::Java => {
            kind == "variable_declarator"
                && ancestor_matches(node, 4, |ancestor| {
                    ancestor.text().trim_start().starts_with("final ")
                        || ancestor.text().contains(" final ")
                })
        }
        Language::Go => kind == "const_spec",
        Language::Rust => kind == "const_item",
        Language::Python => kind == "assignment",
        Language::Php => kind == "assignment_expression",
    }
}

fn is_mutable_declaration<D: Doc>(node: &Node<'_, D>, language: Language) -> bool {
    let kind = node.kind();
    let kind = kind.as_ref();
    match language {
        Language::C | Language::Cpp => false,
        Language::Kotlin => false,
        Language::Javascript | Language::Typescript | Language::Tsx => {
            kind == "variable_declarator" && !is_constant_declarator(node, language)
        }
        Language::Csharp | Language::Java => {
            kind == "variable_declarator" && !is_constant_declarator(node, language)
        }
        Language::Go => matches!(kind, "var_spec" | "short_var_declaration"),
        Language::Rust => kind == "let_declaration",
        Language::Php => kind == "augmented_assignment_expression",
        Language::Python => matches!(kind, "augmented_assignment" | "named_expression"),
    }
}

fn declaration_name<D: Doc>(node: &Node<'_, D>) -> Option<String> {
    let name = node.field("name").or_else(|| node.field("left"))?;
    let name = name.text().trim().to_string();
    is_identifier(&name).then_some(name)
}

fn declaration_initializer<'tree, D: Doc>(
    node: &Node<'tree, D>,
    language: Language,
) -> Option<Node<'tree, D>> {
    if let Some(initializer) = node
        .field("value")
        .or_else(|| node.field("initializer"))
        .or_else(|| {
            matches!(language, Language::Python | Language::Php)
                .then(|| node.field("right"))
                .flatten()
        })
    {
        return Some(initializer);
    }
    if language != Language::Csharp {
        return None;
    }
    let name = node.field("name")?;
    node.children()
        .filter(|child| child.is_named() && child.range() != name.range())
        .last()
}

fn is_parameter_identifier<D: Doc>(node: &Node<'_, D>) -> bool {
    if !matches!(node.kind().as_ref(), "identifier" | "variable_name") {
        return false;
    }
    node.ancestors().take(2).any(|ancestor| {
        let kind = ancestor.kind();
        let kind = kind.as_ref();
        kind.contains("parameter")
    })
}

fn ancestor_matches<D: Doc>(
    node: &Node<'_, D>,
    maximum: usize,
    mut predicate: impl FnMut(&Node<'_, D>) -> bool,
) -> bool {
    node.ancestors()
        .take(maximum)
        .any(|ancestor| predicate(&ancestor))
}

fn declaration_scope<D: Doc>(node: &Node<'_, D>, root: &Node<'_, D>) -> Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "block"
                    | "compound_statement"
                    | "statement_block"
                    | "class_body"
                    | "declaration_list"
                    | "program"
                    | "module"
            )
        })
        .map(|ancestor| ancestor.range())
        .unwrap_or_else(|| root.range())
}

fn direct_boolean(text: &str) -> Option<bool> {
    match text {
        "true" | "True" => Some(true),
        "false" | "False" => Some(false),
        _ => None,
    }
}

fn is_null(text: &str) -> bool {
    matches!(text, "null" | "nil" | "None")
}

fn is_number(text: &str, kind: &str) -> bool {
    let numeric_kind = kind.contains("number")
        || kind.contains("integer")
        || kind.contains("float")
        || kind.contains("decimal")
        || kind.contains("real_literal");
    numeric_kind
        && text
            .trim_start_matches(['+', '-'])
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
}

fn is_signed_number(kind: &str, text: &str) -> bool {
    matches!(kind, "unary_expression" | "unary_operator")
        && (text.starts_with('+') || text.starts_with('-'))
}

fn is_plain_string(text: &str, kind: &str) -> bool {
    !is_interpolated_string(text, kind) && kind.contains("string") && quoted(text)
}

fn is_interpolated_string(text: &str, kind: &str) -> bool {
    (kind == "encapsed_string" && text.contains('$'))
        || kind.contains("template")
        || kind.contains("interpolated")
        || (text.starts_with('`') && text.contains("${"))
        || ((text.starts_with("f\"")
            || text.starts_with("F\"")
            || text.starts_with("f'")
            || text.starts_with("F'")
            || text.starts_with("$\"")
            || text.starts_with("$@\"")
            || text.starts_with("@$\""))
            && text.contains('{'))
}

fn quoted(text: &str) -> bool {
    let text = text.trim();
    (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('\'') && text.ends_with('\''))
        || (text.starts_with('`') && text.ends_with('`'))
}

fn decode_string(text: &str) -> String {
    let text = text.trim();
    let body = if text.len() >= 2 {
        &text[1..text.len() - 1]
    } else {
        text
    };
    body.replace("\\n", "\n")
        .replace("\\r", "\r")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\'", "'")
        .replace("\\\\", "\\")
}

fn is_parenthesized(kind: &str) -> bool {
    kind.contains("parenthesized")
}

fn is_transparent_wrapper(kind: &str) -> bool {
    matches!(kind, "argument" | "expression_list" | "equals_value_clause")
}

fn is_string_concatenation<D: Doc>(node: &Node<'_, D>) -> bool {
    matches!(
        node.kind().as_ref(),
        "binary_expression" | "additive_expression" | "binary_operator"
    ) && node.field("left").is_some()
        && node.field("right").is_some()
}

fn operator_between<D: Doc>(node: &Node<'_, D>, left: &Node<'_, D>, right: &Node<'_, D>) -> String {
    let text = node.text();
    let start = left.range().end.saturating_sub(node.range().start);
    let end = right.range().start.saturating_sub(node.range().start);
    text.get(start..end).unwrap_or_default().trim().to_string()
}

fn is_array_kind(kind: &str) -> bool {
    matches!(kind, "array" | "list" | "array_initializer")
}

fn is_map_kind(kind: &str) -> bool {
    matches!(kind, "object" | "dictionary" | "map_literal")
}

fn is_pair_kind(kind: &str) -> bool {
    matches!(kind, "pair" | "keyed_element" | "dictionary_splat")
}

fn interpolation_body(text: &str) -> (&str, bool) {
    let text = text.trim();
    if text.starts_with('`') && text.ends_with('`') {
        return (&text[1..text.len() - 1], true);
    }
    let quote = text.find(['"', '\'']).unwrap_or(0);
    let end = text.len().saturating_sub(1);
    (&text[(quote + 1).min(end)..end], false)
}

fn next_interpolation(body: &str, cursor: usize, javascript: bool) -> Option<(usize, usize)> {
    if javascript {
        let open = body[cursor..].find("${")? + cursor;
        Some((open, open + 2))
    } else {
        let mut offset = cursor;
        while let Some(relative) = body[offset..].find('{') {
            let open = offset + relative;
            if body[open..].starts_with("{{") {
                offset = open + 2;
                continue;
            }
            return Some((open, open + 1));
        }
        None
    }
}

fn unescape_braces(value: &str) -> String {
    value.replace("{{", "{").replace("}}", "}")
}

fn scalar_text(value: &LiteralValue) -> Option<String> {
    match value {
        LiteralValue::Boolean(value) => Some(value.to_string()),
        LiteralValue::Number(value) | LiteralValue::String(value) | LiteralValue::Enum(value) => {
            Some(value.clone())
        }
        LiteralValue::Null => Some("null".to_string()),
        LiteralValue::Array(_) | LiteralValue::Map(_) => None,
    }
}

fn fragments_for(evaluation: &LiteralEvaluation) -> Vec<String> {
    if let Some(value) = evaluation.value.as_ref().and_then(scalar_text) {
        vec![value]
    } else {
        evaluation.constant_fragments.clone()
    }
}

fn known(value: LiteralValue) -> LiteralEvaluation {
    LiteralEvaluation {
        state: LiteralState::Known,
        value: Some(value),
        constant_fragments: Vec::new(),
        references: Vec::new(),
    }
}

fn partial(constant_fragments: Vec<String>, references: Vec<String>) -> LiteralEvaluation {
    LiteralEvaluation {
        state: LiteralState::Partial,
        value: None,
        constant_fragments,
        references,
    }
}

fn unknown(references: Vec<String>) -> LiteralEvaluation {
    LiteralEvaluation {
        state: LiteralState::Unknown,
        value: None,
        constant_fragments: Vec::new(),
        references,
    }
}

fn append_unique(output: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !output.contains(&value) {
            output.push(value);
        }
    }
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.strip_prefix('$').unwrap_or(value).chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric())
}

fn is_symbolic_reference(value: &str) -> bool {
    let normalized = value.replace("::", ".");
    normalized.split('.').count() > 1 && normalized.split('.').all(is_identifier)
}

#[cfg(test)]
mod tests {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::{JavaScript, Python};
    use mehscan_core::LiteralValue;

    use super::*;

    fn call_argument<'tree>(
        root: &Node<'tree, ast_grep_core::tree_sitter::StrDoc<JavaScript>>,
        call_name: &str,
    ) -> Node<'tree, ast_grep_core::tree_sitter::StrDoc<JavaScript>> {
        root.dfs()
            .find(|node| {
                node.kind().as_ref() == "call_expression" && node.text().starts_with(call_name)
            })
            .and_then(|call| call.field("arguments"))
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
            .expect("call argument should parse")
    }

    #[test]
    fn evaluates_constants_concatenation_arrays_and_maps() {
        let ast = JavaScript.ast_grep(
            r#"const PREFIX = "safe/";
const COMMAND = PREFIX + "tool";
run(COMMAND);
arraySink([true, 7, "x"]);
mapSink({mode: "safe", enabled: false});"#,
        );
        let root = ast.root();
        let environment = LiteralEnvironment::build(&root, Language::Javascript);
        assert_eq!(
            environment.evaluate(&call_argument(&root, "run")).value,
            Some(LiteralValue::String("safe/tool".to_string()))
        );
        assert!(matches!(
            environment.evaluate(&call_argument(&root, "arraySink")).value,
            Some(LiteralValue::Array(values)) if values.len() == 3
        ));
        assert!(matches!(
            environment.evaluate(&call_argument(&root, "mapSink")).value,
            Some(LiteralValue::Map(values)) if values.len() == 2
        ));
    }

    #[test]
    fn preserves_partial_interpolation_without_claiming_a_value() {
        let ast = JavaScript.ast_grep("run(`prefix/${dynamic}/suffix`);");
        let root = ast.root();
        let environment = LiteralEnvironment::build(&root, Language::Javascript);
        let evaluation = environment.evaluate(&call_argument(&root, "run"));
        assert_eq!(evaluation.state, LiteralState::Partial);
        assert_eq!(evaluation.constant_fragments, ["prefix/", "/suffix"]);
        assert_eq!(evaluation.references, ["dynamic"]);
        assert!(evaluation.value.is_none());
    }

    #[test]
    fn refuses_a_constant_when_a_parameter_can_shadow_it() {
        let ast = JavaScript.ast_grep(
            r#"const COMMAND = "safe";
function review(COMMAND) { run(COMMAND); }"#,
        );
        let root = ast.root();
        let environment = LiteralEnvironment::build(&root, Language::Javascript);
        let evaluation = environment.evaluate(&call_argument(&root, "run"));
        assert_eq!(evaluation.state, LiteralState::Unknown);
        assert_eq!(evaluation.references, ["COMMAND"]);
    }

    #[test]
    fn does_not_treat_numeric_addition_as_string_concatenation() {
        let ast = JavaScript.ast_grep("run(1 + 2);");
        let root = ast.root();
        let environment = LiteralEnvironment::build(&root, Language::Javascript);
        assert_eq!(
            environment.evaluate(&call_argument(&root, "run")).state,
            LiteralState::Unknown
        );
    }

    #[test]
    fn preserves_an_unresolved_qualified_symbol_as_a_reference() {
        let ast = JavaScript.ast_grep("run(crypto.MD5);");
        let root = ast.root();
        let environment = LiteralEnvironment::build(&root, Language::Javascript);
        let evaluation = environment.evaluate(&call_argument(&root, "run"));
        assert_eq!(evaluation.state, LiteralState::Unknown);
        assert_eq!(evaluation.references, ["crypto.MD5"]);
    }

    #[test]
    fn resolves_only_unambiguous_python_local_assignments() {
        let ast = Python.ast_grep(
            r#"def review(dynamic):
    fixed = "https://example.invalid/health"
    run(fixed)
    changed = "first"
    changed = "second"
    run(changed)
    run(dynamic)
"#,
        );
        let root = ast.root();
        let environment = LiteralEnvironment::build(&root, Language::Python);
        let calls = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call")
            .filter(|node| node.text().starts_with("run("))
            .filter_map(|call| call.field("arguments"))
            .filter_map(|arguments| arguments.children().find(|child| child.is_named()))
            .collect::<Vec<_>>();
        assert_eq!(
            environment.evaluate(&calls[0]).value,
            Some(LiteralValue::String(
                "https://example.invalid/health".to_string()
            ))
        );
        assert_eq!(environment.evaluate(&calls[1]).state, LiteralState::Unknown);
        assert_eq!(environment.evaluate(&calls[2]).state, LiteralState::Unknown);
    }
}
