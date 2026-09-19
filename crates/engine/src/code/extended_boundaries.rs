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
    )
}

pub(super) fn accepts<'a>(
    root: &BoundaryNode<'a>,
    node: &BoundaryNode<'a>,
    rule: &str,
    language: Language,
    receiver: Option<&BoundaryNode<'a>>,
) -> bool {
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
