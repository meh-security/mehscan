use std::ops::Range;

use ast_grep_core::{Doc, Node};

/// Byte ranges of comments preserved from the original parsed source.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CommentRanges {
    ranges: Vec<Range<usize>>,
}

impl CommentRanges {
    pub fn from_root<D: Doc>(root: &Node<'_, D>) -> Self {
        let mut ranges = root
            .dfs()
            .filter(|node| is_comment_kind(node.kind().as_ref()))
            .map(|node| node.range())
            .collect::<Vec<_>>();
        ranges.sort_by_key(|range| range.start);
        Self { ranges }
    }

    pub fn is_in_comment(&self, range: Range<usize>) -> bool {
        self.ranges
            .iter()
            .any(|comment| comment.start <= range.start && range.end <= comment.end)
    }

    pub fn comments_in_range(&self, range: Range<usize>) -> Vec<Range<usize>> {
        self.ranges
            .iter()
            .filter(|comment| ranges_overlap(comment, &range))
            .cloned()
            .collect()
    }

    pub fn ranges(&self) -> &[Range<usize>] {
        &self.ranges
    }
}

pub(crate) fn is_comment_kind(kind: &str) -> bool {
    kind.contains("comment")
}

fn ranges_overlap(left: &Range<usize>, right: &Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

#[cfg(test)]
mod tests {
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::JavaScript;

    use super::*;

    #[test]
    fn preserves_line_and_block_comment_ranges() {
        let source = "// exec(x)\nrun(); /* throw y */\n";
        let ast = JavaScript.ast_grep(source);
        let comments = CommentRanges::from_root(&ast.root());
        assert_eq!(comments.ranges().len(), 2);
        assert!(comments.is_in_comment(3..7));
        assert_eq!(comments.comments_in_range(0..source.len()).len(), 2);
        assert!(!comments.is_in_comment(11..16));
        assert!(!comments.is_in_comment(11..31));
        assert_eq!(comments.comments_in_range(11..31).len(), 1);
    }
}
