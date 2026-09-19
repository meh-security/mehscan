use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::Language;

type BoundaryNode<'a> = Node<'a, StrDoc<SupportLang>>;

pub(super) fn is_rule(rule: &str) -> bool {
    matches!(
        rule,
        "java-extended-dynamic-expression"
            | "kotlin-extended-dynamic-expression"
            | "java-extended-script-engine"
            | "java-extended-ldap-query"
            | "kotlin-extended-ldap-query"
            | "php-extended-ldap-query"
            | "c-extended-ldap-query"
            | "cpp-extended-ldap-query"
            | "rust-extended-ldap-query"
            | "go-extended-dynamic-expression"
            | "rust-extended-dynamic-expression"
            | "python-lxml-xpath-query"
    )
}

pub(super) fn accepts<'a>(
    root: &BoundaryNode<'a>,
    node: &BoundaryNode<'a>,
    rule: &str,
    language: Language,
    receiver: Option<&BoundaryNode<'a>>,
) -> bool {
    if rule == "python-lxml-xpath-query" {
        return receiver.is_none_or(|receiver| python_lxml_receiver(root, node, receiver, 8));
    }
    let Some(receiver) = receiver else {
        return matches!(language, Language::C | Language::Cpp | Language::Php)
            && rule.ends_with("ldap-query");
    };
    let method = node
        .field("function")
        .or_else(|| node.field("callee"))
        .map(|callee| callee.text().into_owned())
        .or_else(|| node.field("name").map(|name| name.text().into_owned()))
        .and_then(|text| text.rsplit('.').next().map(str::to_owned))
        .unwrap_or_else(|| {
            node.text()
                .split('(')
                .next()
                .unwrap_or("")
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_string()
        });
    let canonical: &[&str] = if rule == "rust-extended-ldap-query" {
        &["ldap3::Ldap"]
    } else if rule == "go-extended-dynamic-expression" {
        &["github.com/robertkrimen/otto.Otto"]
    } else if rule == "rust-extended-dynamic-expression" {
        &["rhai::Engine"]
    } else if rule.ends_with("ldap-query") {
        &[
            "javax.naming.directory.DirContext",
            "javax.naming.directory.InitialDirContext",
            "javax.naming.ldap.LdapContext",
            "javax.naming.ldap.InitialLdapContext",
        ]
    } else if rule == "java-extended-script-engine" {
        &["javax.script.ScriptEngine"]
    } else {
        match method.as_str() {
            "evaluate" | "parse" => &["groovy.lang.GroovyShell"],
            "parseClass" => &["groovy.lang.GroovyClassLoader"],
            "parseExpression" => &[
                "org.springframework.expression.ExpressionParser",
                "org.springframework.expression.spel.standard.SpelExpressionParser",
            ],
            "createValueExpression" | "createMethodExpression" => {
                &["jakarta.el.ExpressionFactory", "javax.el.ExpressionFactory"]
            }
            _ => &[],
        }
    };
    canonical.iter().any(|canonical| match language {
        Language::Java => {
            super::java_persistence::typed_database_receiver(root, receiver, canonical, 8)
        }
        Language::Kotlin => super::kotlin::jvm::owned(root, receiver, canonical, 8),
        Language::Go => {
            super::extended_database::typed_receiver(root, node, receiver, canonical, language)
        }
        Language::Rust => {
            super::extended_database::typed_receiver(root, node, receiver, canonical, language)
        }
        _ => false,
    })
}

fn python_lxml_receiver<'a>(
    root: &BoundaryNode<'a>,
    use_site: &BoundaryNode<'a>,
    expression: &BoundaryNode<'a>,
    depth: usize,
) -> bool {
    if depth == 0 {
        return false;
    }
    let modules = lxml_module_names(root);
    if matches!(
        expression.kind().as_ref(),
        "call" | "call_expression" | "await"
    ) {
        let Some(function) = expression
            .field("function")
            .or_else(|| expression.children().find(|child| child.is_named()))
        else {
            return false;
        };
        let callee = function.text();
        let Some((base, method)) = callee.rsplit_once('.') else {
            return false;
        };
        return modules.contains(base) && matches!(method, "fromstring" | "parse" | "XML" | "HTML");
    }
    let expression_text = expression.text();
    let observed = expression_text.trim();
    if observed.is_empty()
        || !observed
            .chars()
            .all(|character| character.is_alphanumeric() || matches!(character, '_' | '.'))
    {
        return false;
    }
    let owner = lexical_owner(use_site, root);
    let bindings = root
        .dfs()
        .filter(|candidate| {
            candidate.kind().as_ref() == "assignment"
                && candidate.range().end <= use_site.range().start
                && lexical_owner(candidate, root) == owner
                && candidate
                    .field("left")
                    .is_some_and(|left| left.text().trim() == observed)
        })
        .collect::<Vec<_>>();
    let [binding] = bindings.as_slice() else {
        return false;
    };
    binding
        .field("right")
        .is_some_and(|value| python_lxml_receiver(root, use_site, &value, depth.saturating_sub(1)))
}

fn lxml_module_names(root: &BoundaryNode<'_>) -> std::collections::BTreeSet<String> {
    let mut modules = std::collections::BTreeSet::new();
    for import in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "import_statement" | "import_from_statement"
        )
    }) {
        let text = import.text();
        let text = text.trim();
        if let Some(alias) = text.strip_prefix("from lxml import etree as ") {
            modules.insert(alias.trim().to_string());
        } else if text == "from lxml import etree" {
            modules.insert("etree".to_string());
        } else if let Some(alias) = text.strip_prefix("import lxml.etree as ") {
            modules.insert(alias.trim().to_string());
        } else if text == "import lxml.etree" || text == "import lxml" {
            modules.insert("lxml.etree".to_string());
        }
    }
    modules
}

fn lexical_owner(node: &BoundaryNode<'_>, root: &BoundaryNode<'_>) -> std::ops::Range<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_definition" | "lambda" | "class_definition"
            )
        })
        .map_or_else(|| root.range(), |owner| owner.range())
}
