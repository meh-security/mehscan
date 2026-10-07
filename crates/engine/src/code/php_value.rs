//! Bounded source defaults and static template questions, never safety verdicts.
use super::{PhpContext, PhpNode, function_scope, namespace_scope, unwrap_operand};
use std::collections::BTreeMap;

#[derive(Clone)]
enum Expr {
    Text(String),
    Constant(String),
    Join(Box<Expr>, Box<Expr>),
    Parent(Box<Expr>, usize),
}

#[derive(Default)]
pub(super) struct Constants(BTreeMap<String, Vec<Option<Expr>>>);

impl Constants {
    pub(super) fn collect<'a>(&mut self, path: &str, root: &PhpNode<'a>, context: &PhpContext<'a>) {
        for node in root.dfs() {
            let pair = if context.exact_function(&node, "define") {
                let args = arguments(&node);
                if args.is_empty() {
                    continue;
                }
                let Some(name) = string(&args[0]) else {
                    continue;
                };
                // Unsupported signatures are conflicting defaults, not absent
                // definitions. Keep their named constant unresolved.
                Some((name, (args.len() == 2).then(|| args[1].clone())))
            } else if node.kind().as_ref() == "const_element"
                && !context.namespaced_scope(&namespace_scope(&node, root))
                && !node.ancestors().any(|n| {
                    matches!(
                        n.kind().as_ref(),
                        "class_declaration" | "interface_declaration" | "trait_declaration"
                    )
                })
            {
                let parts: Vec<_> = node.children().filter(|n| n.is_named()).collect();
                (parts.len() == 2).then(|| (parts[0].text().to_string(), Some(parts[1].clone())))
            } else {
                None
            };
            let Some((name, operand)) = pair.filter(|(name, _)| constant_name(name)) else {
                continue;
            };
            let supported = function_scope(&node, root) == root.range()
                && !node.ancestors().any(|n| match n.kind().as_ref() {
                    "for_statement" | "foreach_statement" | "while_statement" | "do_statement"
                    | "switch_statement" | "try_statement" => true,
                    _ => false,
                });
            let value = supported
                .then(|| {
                    operand
                        .as_ref()
                        .and_then(|operand| expression(path, operand, context, 0))
                })
                .flatten();
            self.0.entry(name).or_default().push(value);
        }
    }

    fn evaluate(&self, expr: &Expr, depth: usize) -> Option<String> {
        if depth >= 12 {
            return None;
        }
        match expr {
            Expr::Text(text) => Some(text.clone()),
            Expr::Join(left, right) => Some(format!(
                "{}{}",
                self.evaluate(left, depth + 1)?,
                self.evaluate(right, depth + 1)?
            )),
            Expr::Parent(inner, levels) => {
                let mut value = self.evaluate(inner, depth + 1)?;
                if !value.starts_with("@/") {
                    return None;
                }
                for _ in 0..*levels {
                    value = value.trim_end_matches('/').rsplit_once('/')?.0.to_string();
                    if value == "@" {
                        value.push('/');
                    }
                }
                Some(value)
            }
            Expr::Constant(name) => {
                let definitions = self.0.get(name)?;
                let mut result = None;
                for definition in definitions {
                    let value = self.evaluate(definition.as_ref()?, depth + 1)?;
                    if result.as_ref().is_some_and(|previous| previous != &value) {
                        return None;
                    }
                    result = Some(value);
                }
                result
            }
        }
    }
}

pub(super) fn unresolved_root<'a>(node: &PhpNode<'a>, context: &PhpContext<'a>) -> bool {
    node.dfs().any(|n| {
        n.kind().as_ref() == "name"
            && context
                .constants
                .0
                .get(n.text().as_ref())
                .is_some_and(|definitions| {
                    definitions.iter().any(|expr| {
                        expr.as_ref()
                            .is_none_or(|expr| context.constants.evaluate(expr, 0).is_none())
                    })
                })
    })
}

fn constant_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

fn arguments<'a>(node: &PhpNode<'a>) -> Vec<PhpNode<'a>> {
    node.field("arguments").map_or_else(Vec::new, |args| {
        args.children().filter(|n| n.is_named()).collect()
    })
}

fn operand(mut node: PhpNode<'_>) -> PhpNode<'_> {
    loop {
        node = unwrap_operand(node);
        if node.kind().as_ref() != "argument" {
            return node;
        }
        let Some(child) = node.children().find(|n| n.is_named()) else {
            return node;
        };
        node = child;
    }
}

fn string(node: &PhpNode<'_>) -> Option<String> {
    let node = operand(node.clone());
    if !matches!(node.kind().as_ref(), "string" | "encapsed_string") {
        return None;
    }
    let text = node.text();
    if text.len() < 2 || text.contains(['\\', '$']) || text.chars().any(char::is_control) {
        return None;
    }
    let quote = text.as_bytes()[0];
    (matches!(quote, b'\'' | b'"') && text.as_bytes()[text.len() - 1] == quote)
        .then(|| text[1..text.len() - 1].to_string())
}

fn expression<'a>(
    path: &str,
    node: &PhpNode<'a>,
    context: &PhpContext<'a>,
    depth: usize,
) -> Option<Expr> {
    if depth >= 8 {
        return None;
    }
    let node = operand(node.clone());
    if let Some(text) = string(&node) {
        return Some(Expr::Text(text));
    }
    if node.text().eq_ignore_ascii_case("__DIR__") {
        return Some(Expr::Text(format!(
            "@/{}",
            path.rsplit_once('/').map_or("", |p| p.0)
        )));
    }
    if node.text().eq_ignore_ascii_case("__FILE__") {
        return Some(Expr::Text(format!("@/{path}")));
    }
    if node.kind().as_ref() == "binary_expression"
        && node.field("operator").is_some_and(|n| n.text() == ".")
    {
        return Some(Expr::Join(
            Box::new(expression(path, &node.field("left")?, context, depth + 1)?),
            Box::new(expression(path, &node.field("right")?, context, depth + 1)?),
        ));
    }
    if context.exact_function(&node, "dirname") {
        let args = arguments(&node);
        if !(1..=2).contains(&args.len()) {
            return None;
        }
        let levels = if args.len() == 1 {
            1
        } else {
            operand(args[1].clone()).text().parse::<usize>().ok()?
        };
        if !(1..=4).contains(&levels) {
            return None;
        }
        return Some(Expr::Parent(
            Box::new(expression(path, &args[0], context, depth + 1)?),
            levels,
        ));
    }
    if node.kind().as_ref() == "name"
        && constant_name(node.text().as_ref())
        && !magic_constant(node.text().as_ref())
        && !context.namespaced_scope(&namespace_scope(&node, &context.root))
    {
        return Some(Expr::Constant(node.text().to_string()));
    }
    None
}

pub(super) fn code_target<'a>(
    path: &str,
    node: &PhpNode<'a>,
    context: &PhpContext<'a>,
) -> Option<String> {
    // Direct code-directory paths already have a fact; this adds source defaults.
    if !node.dfs().any(|n| {
        n.kind().as_ref() == "name"
            && constant_name(n.text().as_ref())
            && !magic_constant(n.text().as_ref())
    }) {
        return None;
    }
    let expr = expression(path, node, context, 0)?;
    let value = context.constants.evaluate(&expr, 0)?;
    let value = value.strip_prefix("@/")?;
    if value.contains(['\\', ':']) || value.chars().any(char::is_control) {
        return None;
    }
    let mut parts = Vec::new();
    for part in value.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                parts.pop()?;
            }
            part => parts.push(part),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

pub(super) fn constant_include_expression<'a>(
    path: &str,
    node: &PhpNode<'a>,
    context: &PhpContext<'a>,
) -> bool {
    expression(path, node, context, 0).is_some()
}

pub(super) fn output_context<'a>(context: &PhpContext<'a>, node: &PhpNode<'a>) -> Option<String> {
    let start = node.range().start;
    let owner = function_scope(node, &context.root);
    if context
        .markup_writes
        .iter()
        .any(|(scope, offset)| *scope == owner && *offset < start)
    {
        return None;
    }
    // Read static template text only, never PHP string literals or comments.
    let mut prefix = String::new();
    for (_, text) in context
        .template_texts
        .iter()
        .filter(|(end, _)| *end <= start)
    {
        prefix.push_str(text);
    }
    let lower = prefix.to_ascii_lowercase();
    if let Some(tag) = ["script", "style", "textarea", "title"].iter().find(|tag| {
        lower.rfind(&format!("<{tag}")).is_some_and(|open| {
            lower
                .rfind(&format!("</{tag}"))
                .is_none_or(|close| close < open)
        })
    }) {
        return Some(format!("embedded_context:{tag}"));
    }
    if lower
        .rfind("<!--")
        .is_some_and(|open| lower.rfind("-->").is_none_or(|close| close < open))
    {
        return Some("html_comment".into());
    }
    let mut open = None;
    let mut saw_markup = false;
    let mut quote = None;
    let mut quote_start = 0;
    for (index, byte) in prefix.bytes().enumerate() {
        if open.is_none() {
            if byte == b'<' {
                open = Some(index + 1);
                saw_markup = true;
            }
            continue;
        }
        if Some(byte) == quote {
            quote = None;
        } else if quote.is_none() && matches!(byte, b'\'' | b'"') {
            quote = Some(byte);
            quote_start = index;
        } else if quote.is_none() && byte == b'>' {
            open = None;
        }
    }
    let Some(open) = open else {
        return saw_markup.then(|| "html_text".into());
    };
    let tag = &prefix[open..];
    let Some(quote) = quote else {
        return Some("html_unquoted_or_tag".into());
    };
    let before = tag[..quote_start - open]
        .trim_end()
        .strip_suffix('=')?
        .trim_end();
    let attribute = before
        .rsplit(|c: char| c.is_whitespace())
        .next()?
        .to_ascii_lowercase();
    if attribute.starts_with("on") || matches!(attribute.as_str(), "style" | "srcdoc") {
        return Some(format!("active_attribute:{attribute}"));
    }
    let grammar = if matches!(
        attribute.as_str(),
        "href"
            | "src"
            | "action"
            | "formaction"
            | "poster"
            | "cite"
            | "data"
            | "srcset"
            | "background"
            | "ping"
            | "manifest"
            | "codebase"
            | "archive"
            | "longdesc"
            | "usemap"
            | "profile"
            | "xlink:href"
    ) {
        "url_attribute"
    } else {
        "html_attribute"
    };
    Some(format!("{grammar}:{attribute}:{}", char::from(quote)))
}

fn magic_constant(name: &str) -> bool {
    matches!(
        name,
        "__DIR__"
            | "__FILE__"
            | "__LINE__"
            | "__CLASS__"
            | "__METHOD__"
            | "__FUNCTION__"
            | "__TRAIT__"
            | "__NAMESPACE__"
            | "__PROPERTY__"
    )
}
