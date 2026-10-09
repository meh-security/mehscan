//! Route verbs/exemptions supply surface context, not proof of a protected effect.
use ast_grep_core::{Node, tree_sitter::StrDoc};
use ast_grep_language::SupportLang;
use mehscan_core::{Capability, Capture, Evidence, EvidenceKind, Language};
pub(super) fn annotate(
    language: Language,
    root: &Node<'_, StrDoc<SupportLang>>,
    evidence: &mut [Evidence],
) {
    if language != Language::Csharp {
        return;
    }
    for item in evidence.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "csharp-null-fallback-authorization-review"
                | "csharp-auth-middleware-order-review"
                | "csharp-forwarded-headers-order-review"
                | "csharp-session-cookie-policy-review"
                | "csharp-identity-password-policy-review"
                | "csharp-identity-lockout-policy-review"
                | "csharp-security-token-guid-suitability-review"
        )
    }) {
        item.kind = EvidenceKind::Resource;
        item.tags.push("policy-occurrence:no-weak-decision".into());
    }
    let effects = evidence
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EvidenceKind::Sink | EvidenceKind::SensitiveOperation
            ) && matches!(
                e.capability,
                Capability::DatabaseQuery
                    | Capability::ResourceAccess
                    | Capability::FilesystemRead
                    | Capability::FilesystemWrite
                    | Capability::FileUpload
                    | Capability::ProcessExecution
                    | Capability::DynamicCodeExecution
            )
        })
        .map(|e| (e.id.clone(), e.location.clone(), e.rule_id.clone()))
        .collect::<Vec<_>>();
    let sites = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "attribute" | "invocation_expression"))
        .collect::<Vec<_>>();
    for item in evidence.iter_mut().filter(|e| {
        matches!(
            e.rule_id.as_str(),
            "csharp-anonymous-state-change-review"
                | "csharp-minimal-anonymous-state-change-review"
                | "csharp-antiforgery-exemption-review"
                | "csharp-minimal-antiforgery-exemption-review"
        )
    }) {
        let Some(site) = sites.iter().find(|n| {
            n.range() == (item.location.start.byte_offset..item.location.end.byte_offset)
        }) else {
            continue;
        };
        let scope = if site.kind().as_ref() == "attribute" {
            site.ancestors()
                .find(|n| n.kind().as_ref() == "method_declaration")
        } else {
            Some((*site).clone())
        };
        let Some(scope) = scope else {
            continue;
        };
        let related = effects
            .iter()
            .filter(|(_, location, _)| {
                location.path == item.location.path
                    && location.start.byte_offset >= scope.range().start
                    && location.end.byte_offset <= scope.range().end
            })
            .collect::<Vec<_>>();
        if related.is_empty() {
            item.kind = EvidenceKind::Resource;
            item.tags.push("route-policy:effect-not-established".into());
        } else {
            item.related_evidence
                .extend(related.iter().map(|(id, _, _)| id.clone()));
            let (_, location, rule) = related[0];
            item.captures.insert(
                "effect".into(),
                Capture {
                    text: rule.clone(),
                    location: location.clone(),
                },
            );
            item.tags
                .push("route-policy:observed-sensitive-effect".into());
        }
    }
}
