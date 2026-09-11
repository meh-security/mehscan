use ast_grep_core::{Doc, Node};
use mehscan_core::{
    Availability, AvailabilityState, EvidenceContext, Reachability, ReachabilityState,
};

pub(crate) fn enclosing_symbol<D: Doc>(node: &Node<'_, D>) -> Option<String> {
    const SYMBOL_KINDS: &[&str] = &[
        "method_declaration",
        "constructor_declaration",
        "local_function_statement",
        "function_definition",
        "function_declaration",
        "method_definition",
        "function_item",
    ];
    node.ancestors().find_map(|ancestor| {
        if !SYMBOL_KINDS.contains(&ancestor.kind().as_ref()) {
            return None;
        }
        ancestor.field("name").map(|name| name.text().into_owned())
    })
}

pub(crate) fn unknown_textual_context() -> EvidenceContext {
    EvidenceContext {
        comment: false,
        reachability: Some(Reachability {
            state: ReachabilityState::Unknown,
            reason: None,
        }),
        availability: Some(Availability {
            state: AvailabilityState::Unknown,
            condition: None,
        }),
        ..EvidenceContext::default()
    }
}

pub(crate) fn lexical_declaration_visible_at<D: Doc>(
    declaration: &Node<'_, D>,
    use_site: &Node<'_, D>,
) -> bool {
    let Some(scope) = std::iter::once(declaration.clone())
        .chain(declaration.ancestors())
        .find(|node| {
            matches!(
                node.kind().as_ref(),
                "block"
                    | "for_statement"
                    | "foreach_statement"
                    | "enhanced_for_statement"
                    | "using_statement"
                    | "fixed_statement"
                    | "switch_section"
                    | "switch_block_statement_group"
                    | "try_with_resources_statement"
            )
        })
    else {
        return false;
    };
    let scope = scope.range();
    let use_range = use_site.range();
    scope.start <= use_range.start && use_range.end <= scope.end
}

pub(crate) fn enclosing_type_start<D: Doc>(node: &Node<'_, D>) -> Option<usize> {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
                    | "struct_declaration"
            )
        })
        .map(|owner| owner.range().start)
}
