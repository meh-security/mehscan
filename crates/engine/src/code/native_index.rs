//! Source-ordered syntax slices for native relationships. No inferred control flow.
use std::collections::BTreeMap;

use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;

pub(super) struct NativeIndex<'tree> {
    nodes: BTreeMap<String, Vec<Node<'tree, StrDoc<SupportLang>>>>,
}

impl<'tree> NativeIndex<'tree> {
    pub(super) fn new(root: &Node<'tree, StrDoc<SupportLang>>, kinds: &[&str]) -> Self {
        let mut nodes: BTreeMap<String, Vec<Node<'tree, StrDoc<SupportLang>>>> = BTreeMap::new();
        for node in root.dfs() {
            if kinds.contains(&node.kind().as_ref()) {
                nodes
                    .entry(node.kind().into_owned())
                    .or_default()
                    .push(node);
            }
        }
        Self { nodes }
    }

    pub(super) fn nodes(&self, kind: &str) -> &[Node<'tree, StrDoc<SupportLang>>] {
        self.nodes.get(kind).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Keep the existing strict source bounds, including recovered syntax and
    /// overlapping declarators. This does not replace them with presumed bodies.
    pub(super) fn between(
        &self,
        kind: &str,
        start: usize,
        end: usize,
    ) -> impl Iterator<Item = Node<'tree, StrDoc<SupportLang>>> + '_ {
        let nodes = self.nodes(kind);
        let first = nodes.partition_point(|node| node.range().start <= start);
        nodes[first..]
            .iter()
            .take_while(move |node| node.range().start < end)
            .filter(move |node| node.range().end < end)
            .cloned()
    }
}
