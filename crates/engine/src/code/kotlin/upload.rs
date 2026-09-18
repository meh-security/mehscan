use super::identity::{self, KNode};
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use mehscan_core::{Evidence, QueryProvenance, Resolution, ReviewNeighborhoodFact};

pub(super) fn accepts<'a>(root: &KNode<'a>, rule: &str, node: &KNode<'a>) -> bool {
    let (receiver, method, count) = if let Some(call) = identity::call(node) {
        if call.arguments.iter().any(|a| a.name.is_some()) {
            return false;
        }
        let Some(receiver) = call.callee.children().find(|n| n.is_named()) else {
            return false;
        };
        (
            receiver,
            call.callee
                .text()
                .rsplit('.')
                .next()
                .unwrap_or("")
                .to_owned(),
            call.arguments.len(),
        )
    } else {
        if node.kind().as_ref() != "navigation_expression" {
            return false;
        }
        let Some(receiver) = node.children().find(|n| n.is_named()) else {
            return false;
        };
        (
            receiver,
            node.text().rsplit('.').next().unwrap_or("").to_owned(),
            0,
        )
    };
    let (types, valid): (&[&str], bool) = match rule {
        "kotlin-upload-part" => (
            &[
                "jakarta.servlet.http.HttpServletRequest",
                "javax.servlet.http.HttpServletRequest",
            ],
            method == "getPart" && count == 1 || method == "getParts" && count == 0,
        ),
        "kotlin-upload-filename" => (
            &["jakarta.servlet.http.Part", "javax.servlet.http.Part"],
            matches!(
                method.as_str(),
                "getSubmittedFileName" | "submittedFileName"
            ) && count == 0,
        ),
        "kotlin-upload-content" => (
            &["jakarta.servlet.http.Part", "javax.servlet.http.Part"],
            matches!(method.as_str(), "getInputStream" | "inputStream") && count == 0,
        ),
        "kotlin-script-eval" => (
            &["javax.script.ScriptEngine"],
            method == "eval" && matches!(count, 1 | 2),
        ),
        _ => return false,
    };
    valid
        && types
            .iter()
            .any(|ty| super::jvm::owned(root, &receiver, ty, 12))
}

pub(crate) fn facts(path: &str, source: &str, anchor: &Evidence) -> Vec<ReviewNeighborhoodFact> {
    if !anchor.rule_id.starts_with("kotlin-upload-")
        && anchor.rule_id != "kotlin-script-eval"
        && anchor.rule_id != "kotlin-file-write"
    {
        return vec![];
    }
    let ast = SupportLang::Kotlin.ast_grep(source);
    let root = ast.root();
    if root.dfs().any(|n| n.is_error() || n.is_missing()) {
        return vec![];
    }
    let Some(node) = root.dfs().find(|n| {
        n.range() == (anchor.location.start.byte_offset..anchor.location.end.byte_offset)
            && (accepts(&root, &anchor.rule_id, n)
                || anchor.rule_id == "kotlin-file-write"
                    && super::jvm::accepts(&root, &anchor.rule_id, n))
    }) else {
        return vec![];
    };
    let Some(function) = node
        .ancestors()
        .find(|n| n.kind().as_ref() == "function_declaration")
    else {
        return vec![];
    };
    if function.range().len() > 16384 {
        return vec![];
    }
    if anchor.rule_id == "kotlin-file-write"
        && !function.dfs().any(|n| {
            accepts(&root, "kotlin-upload-part", &n) || accepts(&root, "kotlin-upload-content", &n)
        })
    {
        return vec![];
    }
    vec![ReviewNeighborhoodFact {
        role: "owned_boundary_containing_function_context".into(),
        symbol: identity::name(&function).unwrap_or_default(),
        location: crate::code::matcher::location(path, &function),
        excerpt: format!(
            "Exact SDK operation: {}. Inspect the same uploaded part, destination and rejecting branch, or the same script input and evaluation policy. Client filenames and multipart bytes are untrusted; metadata alone is not file-type validation. ScriptEngine behavior depends on the injected/selected provider. This is containing-function source context, not compiler taint, deployed serving configuration or runtime provider proof.\n{}",
            node.text(),
            function.text()
        ),
        evidence_id: Some(anchor.id.clone()),
        provenance: QueryProvenance {
            resolution: Resolution::Ast,
            engine: "Kotlin owned multipart/script boundary context 1".into(),
        },
    }]
}
