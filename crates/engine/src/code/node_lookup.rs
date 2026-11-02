//! Navigate known source ranges without indexing or rescanning the whole AST.
use std::ops::Range;

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;

/// Equivalent to the last DFS node whose byte range is exactly `range`.
/// Positive-width ranges can lie in only one sibling subtree. Equal-range
/// wrappers form an ancestor chain; descending it retains the last DFS match.
pub(super) fn last_exact<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    range: Range<usize>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if range.is_empty() {
        // Missing nodes can share an offset across sibling boundaries. Keep
        // the established DFS ordering for this exceptional parser case.
        return root.dfs().filter(|node| node.range() == range).last();
    }
    let mut current = root.clone();
    if current.range().start > range.start || current.range().end < range.end {
        return None;
    }
    loop {
        let mut low = 0;
        let mut high = current.children().len();
        while low < high {
            let middle = low + (high - low) / 2;
            let child = current.child(middle)?;
            if child.range().end < range.end {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        let next = current
            .child(low)
            .filter(|child| child.range().start <= range.start && range.end <= child.range().end);
        match next {
            Some(child) => current = child,
            None => return (current.range() == range).then_some(current),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;
    use std::collections::BTreeSet;

    #[test]
    fn exact_navigation_preserves_dfs_identity_across_frontends_and_recovery() {
        let sources = [
            (
                SupportLang::C,
                "/* é */ void f(char *x){g((x));} void h(){g(0);}",
            ),
            (SupportLang::Cpp, "namespace n {void f(){std::move((x));}}"),
            (
                SupportLang::CSharp,
                "class C{void F(string x){db.Query((x));}}",
            ),
            (
                SupportLang::Go,
                "package p\nfunc f(q string){db.Query(q)}\nfunc g(){db.Query(q)}",
            ),
            (
                SupportLang::Java,
                "class C{void f(String x){db.execute((x));}}",
            ),
            (
                SupportLang::JavaScript,
                "function f(x){db.query((x));} const é = ()=>f(x);",
            ),
            (
                SupportLang::TypeScript,
                "function f(x:string){db.query((x));}",
            ),
            (
                SupportLang::Tsx,
                "const f=(x:string)=><span>{db.query(x)}</span>;",
            ),
            (
                SupportLang::Python,
                "def f(x):\n db.execute((x))\ndef g(x):\n return x\n",
            ),
            (
                SupportLang::Rust,
                "fn f(x:&str){db.query((x));} fn g(){f(\"é\");}",
            ),
            (
                SupportLang::PhpMixed,
                "<?php function f($x){$db->query(($x));}",
            ),
            (
                SupportLang::Kotlin,
                "fun f(x:String){db.exec((x))}\nfun g(){f(\"é\")}",
            ),
        ];
        for (language, source) in sources {
            for text in [source.to_string(), format!("{source}\n ({{\"unterminated")] {
                let ast = language.ast_grep(&text);
                let root = ast.root();
                let mut ranges = root
                    .dfs()
                    .map(|node| {
                        let r = node.range();
                        (r.start, r.end)
                    })
                    .collect::<BTreeSet<_>>();
                // Non-node ranges, whitespace boundaries, EOF and outside root.
                for start in 0..=text.len() + 1 {
                    ranges.insert((start, start));
                    ranges.insert((start, start + 1));
                    ranges.insert((start, (start + 3).min(text.len() + 2)));
                }
                for (start, end) in ranges {
                    let range = start..end;
                    let expected = root.dfs().filter(|node| node.range() == range).last();
                    let actual = last_exact(&root, range.clone());
                    assert_eq!(
                        actual.map(|node| node.node_id()),
                        expected.map(|node| node.node_id()),
                        "{language:?} {range:?} {text}"
                    );
                }
            }
        }
    }
}
